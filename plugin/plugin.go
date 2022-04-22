package plugin

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	redisCon "github.com/gomodule/redigo/redis"
	"github.com/miekg/dns"
	"github.com/yoeluk/coredns-redis-backend"
	"github.com/yoeluk/coredns-redis-backend/record"
)

const name = "redis"

var log = clog.NewWithPlugin("redis")

type Plugin struct {
	Redis *redis.Redis
	Next  plugin.Handler

	loadZoneTicker *time.Ticker
	zones          []string
	lastRefresh    time.Time
	lock           sync.Mutex
}

type ZoneIdPair struct {
	ZoneName string
	ZoneId   string
}

func (p *Plugin) Name() string {
	return name
}

func (p *Plugin) Ready() bool {
	ok, err := p.Redis.Ping()
	if err != nil {
		log.Error(err)
	}
	return ok
}

func (p *Plugin) MakeZoneIdPair(zoneKey string) (*ZoneIdPair, error) {
	parts := strings.Split(zoneKey, ":")
	zoneParts := make([]string, 0, 0)
	for _, part := range parts {
		if !strings.HasPrefix(part, "__") && part != p.Redis.GetReferralPrefix() {
			zoneParts = append(zoneParts, part)
		}
	}
	if len(zoneParts) == 2 {
		log.Debugf("the zoneParts are: %s", strings.Join(zoneParts, ", "))
		zoneIdPair := &ZoneIdPair{zoneParts[0], zoneParts[1]}
		return zoneIdPair, nil
	}
	return &ZoneIdPair{}, fmt.Errorf("error construction zonePairId from %s", zoneKey)
}

func (p *Plugin) findBestZoneIdPair(qName string, qType uint16, ecsIp net.IP, zoneKeys []string, conn redisCon.Conn) (
	zoneIdPair *ZoneIdPair, zone *record.Zone, zoneRecords *record.Records, vpcNetStr string, location string, qTypeExist bool) {
	for _, zk := range shuffleKeys(zoneKeys) {
		zip, err := p.MakeZoneIdPair(zk)
		zid := zip.ZoneId
		zn := zip.ZoneName
		var found bool
		vpcAssocs, err := p.Redis.GetVpcZoneAssociation(zid, conn)
		for _, as := range *vpcAssocs {
			if err != nil {
				log.Debugf(err.Error())
				continue
			}

			log.Debugf("loading zones for zone: %s, with zoneId: %s", zn, zid)
			z := p.Redis.LoadZoneC(zn, zid, false, conn)
			if z == nil {
				log.Debugf("unable to load zone: %s", zn)
				continue
			}

			l := p.Redis.FindLocation(qName, z)
			if l == "" {
				log.Debugf("location %s not foundKeys for zone: %s", qName, z)
				continue
			}

			zr := p.Redis.LoadZoneRecordsC(l, zid, z, conn)
			e := zr.TypeExist(dns.Type(qType).String())
			if e {
				zoneIdPair = zip
				zone = z
				location = l
				qTypeExist = e
				zoneRecords = zr
				_, vpcNet, err := net.ParseCIDR(as.VpcCidr)
				vpcNetStr = vpcNet.String()
				if err == nil && vpcNet.Contains(ecsIp) {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	return
}

func (p *Plugin) handleNotfound(qName string, qType uint16, state request.Request, answers []dns.RR, r *dns.Msg, extras []dns.RR, w dns.ResponseWriter) (int, error) {
	log.Debugf("unable to load zone: %s, qtype: %s", qName, dns.Type(qType))
	authorities := make([]dns.RR, 0, 0)
	if qType == dns.TypeA && qName != "." {
		_, exist, err := p.Redis.CheckDomainExist(qName, "*")
		if !exist && err == nil {
			log.Debugf("unknown domain, sending domain error for: %s, with type: %s", qName, dns.Type(qType))
			return p.Redis.ErrorResponse(state, dns.RcodeNameError, nil)
		} else if err != nil {
			log.Error("got an error searching for tld:")
			return p.Redis.ErrorResponse(state, dns.RcodeServerFailure, err)
		}
	}
	rec := new(dns.NS)
	rec.Hdr = dns.RR_Header{Name: dns.Fqdn(qName), Rrtype: dns.TypeNS,
		Class: dns.ClassINET, Ttl: 300}
	rec.Ns = p.Redis.RootHost
	switch qType {
	case dns.TypeA:
		log.Debugf("A query where zone for query % was not found but found zones containing it; sending referral for with pathfinder-dns as authority", qName)
		authorities = append(authorities, rec)
	case dns.TypeNS:
		log.Debugf("NS query where zone for query % was not found; synthesizing pathfinder NS record for qname: %s", qName)
		answers = append(answers, rec)
	default:
		return p.Redis.ErrorResponse(state, dns.RcodeNameError, nil)
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, true, true
	m.Answer = append(m.Answer, answers...)
	m.Ns = append(m.Ns, authorities...)
	m.Extra = append(m.Extra, extras...)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func (p *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{Req: r, W: w}
	qName := state.Name()
	qType := state.QType()

	if qName == "" || qType == dns.TypeNone {
		return plugin.NextOrFailure(qName, p.Next, ctx, w, r)
	}

	var conn redisCon.Conn
	defer func() {
		if conn == nil {
			return
		}
		_ = conn.Close()
	}()

	opt := r.IsEdns0()

	var ecsIp net.IP

	for _, e := range opt.Option {
		if subnet, ok := e.(*dns.EDNS0_SUBNET); ok {
			log.Debugf("the client subnet/ip, %s", subnet.Address.String())
			ecsIp = subnet.Address.To4()
		}
	}

	answers := make([]dns.RR, 0, 0)
	extras := make([]dns.RR, 0, 10)
	// When a DNS request arrives
	// Check in Redis first, if domain not exist, go to next plugin
	// Else continue to serve already loaded zones
	conn = p.Redis.Pool.Get()
	zoneKeys, foundKeys, err := p.Redis.CheckZoneInDb(qName, dns.Type(qType).String()) // retrieve all the zone keys with ids for qName
	if err != nil {
		fmt.Println(err)
		return p.Redis.ErrorResponse(state, dns.RcodeServerFailure, err)
	} else if !foundKeys {
		return p.handleNotfound(qName, qType, state, answers, r, extras, w)
	}

	//isReferral, err := p.Redis.CheckReferralNeeded(qName)
	//
	//if err != nil {
	//	fmt.Println(err)
	//	return p.Redis.ErrorResponse(state, dns.RcodeServerFailure, err)
	//} else if isReferral {
	//
	//	zone, records := p.Redis.LoadReferralZoneC(qName, conn)
	//
	//	if zone == nil {
	//		fmt.Printf("unable to load zone for question: %s\n", qName)
	//		return p.Redis.ErrorResponse(state, dns.RcodeServerFailure, nil)
	//	}
	//
	//	authority := make([]dns.RR, 0, 10)
	//	extras := make([]dns.RR, 0, 10)
	//	authority, extras = p.Redis.NS(zone.Name, zone, records, p.zones, conn)
	//
	//	m := new(dns.Msg)
	//	m.SetReply(r)
	//	m.Authoritative, m.RecursionAvailable, m.Compress = true, true, true
	//	m.Ns = append(m.Ns, authority[:2]...)
	//	m.Extra = append(m.Extra, extras...)
	//	state.SizeAndDo(m)
	//	m = state.Scrub(m)
	//	_ = w.WriteMsg(m)
	//
	//	log.Debugf("A referral is configured for this record; sending referral for qname: %s with configured authority", qName)
	//
	//	return dns.RcodeSuccess, nil
	//}

	zoneIdPair, zone, zoneRecords, vpcNetStr, location, qTypeExist := p.findBestZoneIdPair(qName, qType, ecsIp, zoneKeys, conn)

	if err != nil || zoneIdPair == nil || zone == nil || location == "" || !qTypeExist {
		log.Debugf("couldn't find the record")
		return p.Redis.ErrorResponse(state, dns.RcodeNameError, err)
	}

	log.Debugf("using zoneId %s with vpcCidr % for client subnet (ip) %s", zoneIdPair.ZoneId, vpcNetStr, ecsIp)

	zoneId := zoneIdPair.ZoneId
	zoneRecords.MakeFqdn(zone.Name)

	switch qType {
	case dns.TypeSOA:
		answers, extras = p.Redis.SOA(zone, zoneRecords)
	case dns.TypeA:
		answers, extras = p.Redis.A(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypeAAAA:
		answers, extras = p.Redis.AAAA(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypeCNAME:
		answers, extras = p.Redis.CNAME(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypeTXT:
		answers, extras = p.Redis.TXT(qName, zone, zoneRecords)
	case dns.TypeNS:
		answers, extras = p.Redis.NS(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypeMX:
		answers, extras = p.Redis.MX(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypeSRV:
		answers, extras = p.Redis.SRV(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypePTR:
		answers, extras = p.Redis.PTR(qName, zoneId, zone, zoneRecords, p.zones, conn)
	case dns.TypeCAA:
		answers, extras = p.Redis.CAA(qName, zone, zoneRecords)

	default:
		return p.Redis.ErrorResponse(state, dns.RcodeNotImplemented, nil)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, true, true
	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func shuffleKeys[E any](ks []E) []E {
	rand.Seed(time.Now().Unix())
	rand.Shuffle(len(ks), func(i, j int) {
		ks[i], ks[j] = ks[j], ks[i]
	})
	return ks
}
