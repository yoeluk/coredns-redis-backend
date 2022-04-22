package redis

import (
	"encoding/json"
	"fmt"
	"github.com/coredns/coredns/plugin/pkg/log"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/yoeluk/coredns-redis-backend/record"
	"github.com/yoeluk/coredns-redis-backend/vpc"

	redisCon "github.com/gomodule/redigo/redis"
)

const (
	DefaultTtl            = 3600
	DefaultReferralPrefix = "referral:"
	DefaultVpcPrefix      = "__vpc:"
)

type Redis struct {
	Pool           *redisCon.Pool
	address        string
	username       string
	password       string
	connectTimeout int
	readTimeout    int
	KeyPrefix      string
	keySuffix      string
	referralPrefix string
	VpcPrefix      string
	RootHost       string
	DefaultTtl     int
}

func New() *Redis {
	var redis = Redis{}
	redis.SetKeySuffix("")
	redis.SetRootHost("pathfinder-dns.bluecat.io.")
	redis.referralPrefix = DefaultReferralPrefix
	redis.SetVpcPrefix(DefaultVpcPrefix)
	return &redis
}

// SetAddress sets the address (host:port) to the redis backend
func (redis *Redis) SetAddress(a string) {
	redis.address = a
}

// SetUsername sets the username for the redis connection (optional)
func (redis Redis) SetUsername(u string) {
	redis.username = u
}

// SetPassword set the password for the redis connection (optional)
func (redis *Redis) SetPassword(p string) {
	redis.password = p
}

// SetKeyPrefix sets a prefix for all redis-keys (optional)
func (redis *Redis) SetKeyPrefix(p string) {
	redis.KeyPrefix = p
}

// SetKeySuffix sets a suffix for all redis-keys (optional)
func (redis *Redis) SetKeySuffix(s string) {
	redis.keySuffix = s
}

// SetConnectTimeout sets a timeout in ms for the connection setup (optional)
func (redis *Redis) SetConnectTimeout(t int) {
	redis.connectTimeout = t
}

// SetReadTimeout sets a timeout in ms for redis read operations (optional)
func (redis *Redis) SetReadTimeout(t int) {
	redis.readTimeout = t
}

// SetDefaultTtl sets a default TTL for records in the redis backend (default 3600)
func (redis *Redis) SetDefaultTtl(t int) {
	redis.DefaultTtl = t
}

// SetReferralPrefix the referral prefix where referral queries are indicated
func (redis *Redis) SetReferralPrefix(s string) {
	redis.referralPrefix = s
}

func (redis *Redis) GetReferralPrefix() string {
	return redis.referralPrefix
}

func (redis *Redis) SetRootHost(s string) {
	redis.RootHost = s
}

func (redis *Redis) SetVpcPrefix(s string) {
	redis.VpcPrefix = s
}

// Ping sends a "PING" command to the redis backend
// and returns (true, nil) if redis response
// is 'PONG'. Otherwise Ping return false and
// an error
func (redis *Redis) Ping() (bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	r, err := conn.Do("PING")
	s, err := redisCon.String(r, err)
	if err != nil {
		return false, err
	}
	if s != "PONG" {
		return false, fmt.Errorf("unexpected response, expected 'PONG', got: %s", s)
	}
	return true, nil
}

func (redis *Redis) ErrorResponse(state request.Request, rcode int, err error) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, rcode)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	state.SizeAndDo(m)
	_ = state.W.WriteMsg(m)
	// Return success as the rcode to signal we have written to the client.
	return dns.RcodeSuccess, err
}

func (redis *Redis) SOA(z *record.Zone, rec *record.Records) (answers, extras []dns.RR) {
	soa := new(dns.SOA)

	soa.Hdr = dns.RR_Header{Name: dns.Fqdn(z.Name), Rrtype: dns.TypeSOA,
		Class: dns.ClassINET, Ttl: redis.ttl(rec.SOA.Ttl)}
	soa.Ns = rec.SOA.MName
	soa.Mbox = rec.SOA.RName
	soa.Serial = rec.SOA.Serial
	soa.Refresh = rec.SOA.Refresh
	soa.Retry = rec.SOA.Retry
	soa.Expire = rec.SOA.Expire
	soa.Minttl = rec.SOA.MinTtl
	if soa.Serial == 0 {
		soa.Serial = record.DefaultSerial()
	}
	answers = append(answers, soa)
	return
}

func (redis *Redis) A(name string, zoneId string, z *record.Zone, rec *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	if len(rec.A) > 0 {
		for _, a := range rec.A {
			if a.Ip == nil {
				continue
			}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: redis.ttl(a.Ttl)}
			r.A = a.Ip
			answers = append(answers, r)
		}
	} else if len(rec.CNAME) > 0 {
		for _, cname := range rec.CNAME {
			if len(cname.Host) == 0 {
				continue
			}
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: redis.ttl(cname.Ttl)}
			r.Target = dns.Fqdn(cname.Host)
			answers = append(answers, r)
			answers = append(answers, redis.getExtras(cname.Host, zoneId, z, zones, conn, "a", cname.Host)...)
		}
	}
	return
}

func (redis Redis) AAAA(name string, zoneId string, z *record.Zone, rec *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	if len(rec.AAAA) > 0 {
		for _, aaaa := range rec.AAAA {
			if aaaa.Ip == nil {
				continue
			}
			r := new(dns.AAAA)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA,
				Class: dns.ClassINET, Ttl: redis.ttl(aaaa.Ttl)}
			r.AAAA = aaaa.Ip
			answers = append(answers, r)
		}
	} else if len(rec.CNAME) > 0 {
		for _, cname := range rec.CNAME {
			if len(cname.Host) == 0 {
				continue
			}
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: redis.ttl(cname.Ttl)}
			r.Target = dns.Fqdn(cname.Host)
			answers = append(answers, r)
			answers = append(answers, redis.getExtras(cname.Host, zoneId, z, zones, conn, "aaaa", cname.Host)...)
		}
	}
	return
}

func (redis *Redis) CNAME(name string, _ *record.Zone, record *record.Records, _ []string, _ redisCon.Conn, excluding ...string) (answers, extras []dns.RR) {
	for _, cname := range record.CNAME {
		skip := false
		for _, e := range excluding {
			if name == e || cname.Host == e {
				skip = true
				continue
			}
		}
		if len(cname.Host) == 0 || skip {
			continue
		}
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: redis.ttl(cname.Ttl)}
		r.Target = dns.Fqdn(cname.Host)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) TXT(name string, _ *record.Zone, record *record.Records) (answers, extras []dns.RR) {
	for _, txt := range record.TXT {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: redis.ttl(txt.Ttl)}
		r.Txt = split255(txt.Text)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) NS(name string, zoneId string, z *record.Zone, record *record.Records, zones []string, conn redisCon.Conn) (nss, extras []dns.RR) {
	for _, ns := range record.NS {
		if len(ns.Host) == 0 {
			continue
		}
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: redis.ttl(ns.Ttl)}
		r.Ns = ns.Host
		nss = append(nss, r)
		extras = append(extras, redis.getExtras(ns.Host, zoneId, z, zones, conn, "a")...)
	}
	return
}

func (redis *Redis) MX(name string, zoneId string, z *record.Zone, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, mx := range record.MX {
		if len(mx.Host) == 0 {
			continue
		}
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: redis.ttl(mx.Ttl)}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(mx.Host, zoneId, z, zones, conn, "")...)
	}
	return
}

func (redis *Redis) SRV(name string, zoneId string, z *record.Zone, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, srv := range record.SRV {
		if len(srv.Target) == 0 {
			continue
		}
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSRV,
			Class: dns.ClassINET, Ttl: redis.ttl(srv.Ttl)}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(srv.Target, zoneId, z, zones, conn, "")...)
	}
	return
}

func (redis *Redis) PTR(name string, zoneId string, z *record.Zone, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, ptr := range record.PTR {
		if len(ptr.Name) == 0 {
			continue
		}
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypePTR,
			Class: dns.ClassINET, Ttl: redis.ttl(ptr.Ttl)}
		r.Ptr = ptr.Name
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(ptr.Name, zoneId, z, zones, conn, "")...)
	}
	return
}

func (redis *Redis) CAA(name string, _ *record.Zone, record *record.Records) (answers, extras []dns.RR) {
	if record == nil {
		return
	}
	for _, caa := range record.CAA {
		if caa.Value == "" || caa.Tag == "" {
			continue
		}
		r := new(dns.CAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCAA, Class: dns.ClassINET}
		r.Flag = caa.Flag
		r.Tag = caa.Tag
		r.Value = caa.Value
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) getExtras(name string, zoneId string, z *record.Zone, zones []string, conn redisCon.Conn, extraType string, excluding ...string) []dns.RR {
	location := redis.FindLocation(name, z)
	if location == "" {
		zoneName := plugin.Zones(zones).Matches(name)
		if zoneName == "" {
			zones, err, _ := redis.LoadZoneNamesC(name, conn)
			if err != nil {
				return nil
			}
			zoneName = plugin.Zones(zones).Matches(name)
			if zoneName == "" {
				return nil
			}
		}

		z2 := redis.LoadZoneC(zoneName, zoneId, false, conn)
		location = redis.FindLocation(name, z2)
		if location == "" {
			return nil
		}
		return redis.fillExtras(name, zoneId, z2, location, zones, conn, extraType, excluding...)
	}
	return redis.fillExtras(name, zoneId, z, location, zones, conn, extraType, excluding...)
}

func (redis *Redis) fillExtras(name string, zoneId string, z *record.Zone, location string, zones []string, conn redisCon.Conn, extraType string, excluding ...string) []dns.RR {
	var (
		zoneRecords *record.Records
		answers     []dns.RR
	)

	zoneRecords = redis.LoadZoneRecordsC(location, zoneId, z, conn)
	zoneRecords.MakeFqdn(z.Name)

	if zoneRecords == nil {
		return nil
	}
	if extraType == "a" {
		a, _ := redis.A(name, zoneId, z, zoneRecords, zones, conn)
		answers = append(answers, a...)
	}
	if extraType == "aaaa" {
		aaaa, _ := redis.AAAA(name, zoneId, z, zoneRecords, zones, conn)
		answers = append(answers, aaaa...)
	}
	cname, _ := redis.CNAME(name, z, zoneRecords, zones, conn, excluding...)
	answers = append(answers, cname...)
	return answers
}

func (redis *Redis) ttl(ttl int) uint32 {
	if ttl >= 0 {
		return uint32(ttl)
	}
	// todo: return SOA minTTL
	if redis.DefaultTtl >= 0 {
		return uint32(redis.DefaultTtl)
	}
	return DefaultTtl
}

func (redis *Redis) FindLocation(query string, z *record.Zone) string {
	var (
		ok                                 bool
		closestEncloser, sourceOfSynthesis string
	)

	// request for zone records
	if query == z.Name {
		return query
	}

	query = strings.TrimSuffix(query, "."+z.Name)

	if _, ok = z.Locations[query]; ok {
		return query
	}

	closestEncloser, sourceOfSynthesis, ok = splitQuery(query)
	for ok {
		ceExists := keyMatches(closestEncloser, z) || keyExists(closestEncloser, z)
		ssExists := keyExists(sourceOfSynthesis, z)
		if ceExists {
			if ssExists {
				return sourceOfSynthesis
			} else {
				return ""
			}
		} else {
			closestEncloser, sourceOfSynthesis, ok = splitQuery(closestEncloser)
		}
	}
	return ""
}

// Connect establishes a connection to the redis-backend. The configuration must have
// been done before.
func (redis *Redis) Connect() error {
	redis.Pool = &redisCon.Pool{
		Dial: func() (redisCon.Conn, error) {
			var opts []redisCon.DialOption
			if redis.username != "" {
				opts = append(opts, redisCon.DialUsername(redis.username))
			}
			if redis.password != "" {
				opts = append(opts, redisCon.DialPassword(redis.password))
			}
			if redis.connectTimeout != 0 {
				opts = append(opts, redisCon.DialConnectTimeout(time.Duration(redis.connectTimeout)*time.Millisecond))
			}
			if redis.readTimeout != 0 {
				opts = append(opts, redisCon.DialReadTimeout(time.Duration(redis.readTimeout)*time.Millisecond))
			}

			return redisCon.Dial("tcp", redis.address, opts...)
		},
	}
	c := redis.Pool.Get()
	defer c.Close()

	if c.Err() != nil {
		return c.Err()
	}

	res, err := c.Do("PING")
	pong, err := redisCon.String(res, err)
	if err != nil {
		return err
	}
	if pong != "PONG" {
		return fmt.Errorf("unexpexted result, 'PONG' expected: %s", pong)
	}
	return nil
}

func (redis *Redis) GetVpcZoneAssociation(zoneId string, conn redisCon.Conn) (*[]vpc.ZoneAssociation, error) {
	var (
		reply    interface{}
		err      error
		value    string
		vpcAssoc []vpc.ZoneAssociation
	)
	reply, err = conn.Do("GET", redis.VpcPrefix+redis.KeyPrefix+zoneId)
	value, err = redisCon.String(reply, err)
	vpcAssoc = make([]vpc.ZoneAssociation, 0, 0)
	err = json.Unmarshal([]byte(value), &vpcAssoc)
	if err == nil {
		return &vpcAssoc, nil
	}
	return &vpcAssoc, err
}

// LoadZoneC loads a zone from the backend. The loading of the records is optional, if omitted
// the result contains only the locations in the zone.
func (redis *Redis) LoadZoneC(zone string, zoneId string, withRecord bool, conn redisCon.Conn) *record.Zone {
	var (
		reply  interface{}
		err    error
		values []string
	)

	reply, err = conn.Do("HKEYS", redis.Key(zone, ":"+zoneId))
	values, err = redisCon.Strings(reply, err)
	if err != nil || len(values) == 0 {
		return nil
	}

	z := new(record.Zone)
	z.Name = zone
	z.Locations = make(map[string]record.Records)
	for _, value := range values {
		if withRecord {
			z.Locations[value] = *redis.LoadZoneRecordsC(value, zoneId, z, conn)
		} else {
			z.Locations[value] = record.Records{}
		}
	}

	return z
}

// LoadZoneRecordsC loads a zone record from the backend for a given zone
func (redis *Redis) LoadZoneRecordsC(key string, zoneId string, z *record.Zone, conn redisCon.Conn) *record.Records {
	var (
		err   error
		reply interface{}
		val   string
	)

	var label string
	if key == z.Name {
		label = "@"
	} else {
		label = key
	}

	reply, err = conn.Do("HGET", redis.Key(z.Name, ":"+zoneId), label)
	if err != nil {
		return nil
	}
	val, err = redisCon.String(reply, nil)
	if err != nil {
		return nil
	}
	r := new(record.Records)
	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		fmt.Println("parse error : ", val, err)
		return nil
	}
	return r
}

// CheckReferralNeeded check if the qName needs to be referred to another authority
func (redis *Redis) CheckReferralNeeded(name string) (bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	reply, err := conn.Do("EXISTS", redis.referralPrefix+redis.KeyPrefix+name)
	zoneCount, err := redisCon.Int(reply, err)
	if err != nil {
		return false, err
	}

	return zoneCount > 0, nil
}

func (redis *Redis) CheckDomainExist(domain string, wildcard string) ([]string, bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()
	iter := 0
	keys := make([]string, 0, 0)
	searchPattern := redis.KeyPrefix + wildcard + domain + ":*"
	log.Debugf("searching for zoneKey with pattern: %s", searchPattern)
	for {
		arr, err := conn.Do("SCAN", iter, "MATCH", searchPattern, "COUNT", 250)
		reply, err := redisCon.Values(arr, err)
		iter, err = redisCon.Int(reply[0], err)
		replyKeys, err := redisCon.Strings(reply[1], err)
		log.Debugf("found keys: %s", strings.Join(replyKeys, ", "))
		keys = append(keys, replyKeys...)
		if err != nil {
			return keys, len(keys) > 0, err
		}
		if iter == 0 {
			break
		}
	}
	return keys, len(keys) > 0, nil
}

func (redis *Redis) CheckHostname(redisKey string, hostname string) (bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	var (
		reply interface{}
		err   error
		value string
	)

	reply, err = conn.Do("HGET", redisKey, hostname)
	value, err = redisCon.String(reply, err)
	if err != nil {
		return false, err
	}
	return len(value) > 0, nil
}

func (redis *Redis) LoadReferralZoneC(zone string, conn redisCon.Conn) (*record.Zone, *record.Records) {
	var (
		reply             interface{}
		err               error
		authorityZoneName string
		soaRec            *record.Records
		soa               string
	)

	refRecKey := redis.KeyPrefix + redis.referralPrefix + zone
	recKey := "_authority_ref"

	reply, err = conn.Do("HGET", refRecKey, recKey)
	authorityZoneName, err = redisCon.String(reply, err)
	if err != nil {
		log.Debugf("couldn't find the '%s' zone name in map: %s", recKey, refRecKey)
		return nil, nil
	}

	reply, err = conn.Do("HGET", redis.Key(authorityZoneName, ""), "@")
	soa, err = redisCon.String(reply, err)
	if err != nil {
		log.Debugf("couldn't find the '@' key for soa record in zone: %s", redis.Key(authorityZoneName, ""))
		return nil, nil
	}

	soaRec = new(record.Records)
	err = json.Unmarshal([]byte(soa), soaRec)
	if err != nil {
		log.Debugf("parsing %s, with error: %s", authorityZoneName, err)
		return nil, nil
	}

	z := new(record.Zone)
	z.Name = authorityZoneName
	z.Locations = make(map[string]record.Records)
	z.Locations["@"] = *soaRec

	return z, soaRec
}

// CheckZoneInDb check if zone names is saved in the backend
func (redis *Redis) CheckZoneInDb(name string, qType string) ([]string, bool, error) {

	var (
		keys []string
	)

	conn := redis.Pool.Get()
	defer conn.Close()

	names := strings.Split(name, ".")
	zoneName := name

	recordName := names[0]
	if qType == "SOA" {
		recordName = "@"
	}

	log.Debugf("checking for %s in db", zoneName)

	keys = make([]string, 0, 0)
	for _, s := range names {
		reply, _, err := redis.CheckDomainExist(zoneName, "")
		if len(reply) > 0 {
			for _, k := range reply {
				hasHost, err := redis.CheckHostname(k, recordName)
				if err == nil && hasHost {
					log.Debugf("CheckDomainExist for %s in db found %s has hostname %s", zoneName, k, recordName)
					keys = append(keys, k)
				}
			}
			break
		}
		if err != nil || len(zoneName) <= len(s+".") {
			return keys, false, err
		}
		zoneName = zoneName[len(s+"."):]
	}
	log.Debugf("returning found zone keys: %s", strings.Join(keys, ", "))
	return keys, len(keys) > 0, nil
}

//LoadZoneNames calls LoadZoneNamesC with a new redis connection
func (redis *Redis) LoadZoneNames(name string) ([]string, error, bool) {
	conn := redis.Pool.Get()
	defer conn.Close()

	return redis.LoadZoneNamesC(name, conn)
}

// LoadZoneNamesC loads all zone names from the backend that are a subset from the given name.
// Therefore the name is reduced to domain and toplevel domain if necessary.
// It returns an array of zone names, an error if any and a bool that indicates if the redis
// command was executed properly
func (redis *Redis) LoadZoneNamesC(name string, conn redisCon.Conn) ([]string, error, bool) {
	var (
		reply interface{}
		err   error
		zones []string
	)

	query := reduceZoneName(name)
	if query == "" {
		query = name
	}

	reply, err = conn.Do("KEYS", redis.KeyPrefix+"*"+query+redis.keySuffix)
	if err != nil {
		return nil, err, false
	}

	zones, err = redisCon.Strings(reply, err)
	if err != nil {
		return nil, err, true
	}

	for i := range zones {
		zones[i] = strings.TrimPrefix(zones[i], redis.KeyPrefix)
		zones[i] = strings.TrimSuffix(zones[i], redis.keySuffix)
	}
	return zones, nil, true
}

// Key returns the given key with prefix and suffix
func (redis *Redis) Key(zoneName string, suffix string) string {
	return redis.KeyPrefix + dns.Fqdn(zoneName) + suffix
}

func keyExists(key string, z *record.Zone) bool {
	_, ok := z.Locations[key]
	return ok
}

func keyMatches(key string, z *record.Zone) bool {
	for value := range z.Locations {
		if strings.HasSuffix(value, key) {
			return true
		}
	}
	return false
}

// reduceZoneName strips the zone down to top- and second-level
// so we can query the subset from redis. This should give
// no problems unless we want to run a root dns
func reduceZoneName(name string) string {
	name = dns.Fqdn(name)
	split := strings.Split(name[:len(name)-1], ".")
	if len(split) == 0 {
		return ""
	}
	x := len(split) - 2
	if x > 0 {
		name = ""
		for ; x < len(split); x++ {
			name += split[x] + "."
		}
	}
	return name
}

func splitQuery(query string) (string, string, bool) {
	if query == "" {
		return "", "", false
	}
	var (
		splits            []string
		closestEncloser   string
		sourceOfSynthesis string
	)
	splits = strings.SplitAfterN(query, ".", 2)
	if len(splits) == 2 {
		closestEncloser = splits[1]
		sourceOfSynthesis = "*." + closestEncloser
	} else {
		closestEncloser = ""
		sourceOfSynthesis = "*"
	}
	return closestEncloser, sourceOfSynthesis, true
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	var sx []string
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}
