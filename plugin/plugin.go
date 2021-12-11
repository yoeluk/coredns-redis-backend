package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	redisCon "github.com/gomodule/redigo/redis"
	"github.com/miekg/dns"
	redis "github.com/nvlong17/redis"
	"github.com/nvlong17/redis/record"
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

	var zoneName string
	// When a DNS request arrives
	// Check in Redis first, if domain not exist, go to next plugin
	// Else continue to serve already loaded zones
	conn = p.Redis.Pool.Get()
	isBlocked, zoneName, err := p.Redis.CheckZoneInDb(qName)
	if err != nil {
		fmt.Println(err)
		return p.Redis.ErrorResponse(state, qName, dns.RcodeServerFailure, err)
	} else if !isBlocked {
		log.Debugf("zone not in backend: %s", qName)
		// p.checkCache()
		return p.Redis.ErrorResponse(state, qName, dns.RcodeNameError, err)
	}

	isReferral, err := p.Redis.CheckReferralNeeded(qName)

	if err != nil {
		fmt.Println(err)
		return p.Redis.ErrorResponse(state, qName, dns.RcodeServerFailure, err)
	} else if isReferral {

		zone, records := p.Redis.LoadReferralZoneC(qName, conn)

		if zone == nil {
			fmt.Printf("unable to load zone: %s\n", zoneName)
			return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
		}

		authority := make([]dns.RR, 0, 10)
		extras := make([]dns.RR, 0, 10)
		authority, extras = p.Redis.NS(zone.Name, zone, records, p.zones, conn)

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
		m.Ns = append(m.Ns, authority[:2]...)
		m.Extra = append(m.Extra, extras...)
		state.SizeAndDo(m)
		m = state.Scrub(m)
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	zone := p.Redis.LoadZoneC(zoneName, false, conn)
	if zone == nil {
		fmt.Printf("unable to load zone: %s\n", zoneName)
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
	}

	if qType == dns.TypeAXFR {
		log.Debug("zone transfer request (Handler)")
		return p.handleZoneTransfer(zone, p.zones, w, r, conn)
	}

	location := p.Redis.FindLocation(qName, zone)
	if location == "" {
		log.Debugf("location %s not found for zone: %s", qName, zone)
		// p.checkCache()
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeNameError, nil)
	}

	answers := make([]dns.RR, 0, 0)
	extras := make([]dns.RR, 0, 10)
	zoneRecords := p.Redis.LoadZoneRecordsC(location, zone, conn)
	zoneRecords.MakeFqdn(zone.Name)

	switch qType {
	case dns.TypeSOA:
		answers, extras = p.Redis.SOA(zone, zoneRecords)
	case dns.TypeA:
		answers, extras = p.Redis.A(qName, zone, zoneRecords)
	case dns.TypeAAAA:
		answers, extras = p.Redis.AAAA(qName, zone, zoneRecords)
	case dns.TypeCNAME:
		answers, extras = p.Redis.CNAME(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypeTXT:
		answers, extras = p.Redis.TXT(qName, zone, zoneRecords)
	case dns.TypeNS:
		answers, extras = p.Redis.NS(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypeMX:
		answers, extras = p.Redis.MX(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypeSRV:
		answers, extras = p.Redis.SRV(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypePTR:
		answers, extras = p.Redis.PTR(qName, zone, zoneRecords, p.zones, conn)
	case dns.TypeCAA:
		answers, extras = p.Redis.CAA(qName, zone, zoneRecords)

	default:
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeNotImplemented, nil)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func (p *Plugin) handleZoneTransfer(zone *record.Zone, zones []string, w dns.ResponseWriter, r *dns.Msg, conn redisCon.Conn) (int, error) {
	//todo: check and test zone transfer, implement ip-range check
	records := p.Redis.AXFR(zone, zones, conn)
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	tr.TsigSecret = nil
	go func(ch chan *dns.Envelope) {
		j, l := 0, 0

		for i, r := range records {
			l += dns.Len(r)
			if l > redis.MaxTransferLength {
				ch <- &dns.Envelope{RR: records[j:i]}
				l = 0
				j = i
			}
		}
		if j < len(records) {
			ch <- &dns.Envelope{RR: records[j:]}
		}
		close(ch)
	}(ch)

	err := tr.Out(w, r, ch)
	if err != nil {
		fmt.Println(err)
	}
	w.Hijack()
	return dns.RcodeSuccess, nil
}
