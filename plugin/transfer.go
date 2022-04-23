package plugin

import (
	"encoding/json"
	"fmt"
	redisCon "github.com/gomodule/redigo/redis"
	"github.com/miekg/dns"
	"github.com/yoeluk/coredns-redis-backend/record"
	"strings"
)

func (p *Plugin) Persist(zoneName string, rrs []dns.RR) error {
	var conn redisCon.Conn
	conn = p.Redis.Pool.Get()
	defer conn.Close()

	locations := fromRRToRecords(zoneName, rrs)

	for k, v := range locations {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = conn.Do("HSET", p.Redis.KeyPrefix+"secondary:"+zoneName, k, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) RetrieveSOA(zoneName string) *dns.SOA {
	var conn redisCon.Conn
	conn = p.Redis.Pool.Get()
	defer conn.Close()

	soaLabel := "@"
	reply, err := conn.Do("HGET", p.Redis.KeyPrefix+"secondary:"+zoneName, soaLabel)
	val, err := redisCon.String(reply, err)
	if err != nil {
		return nil
	}
	r := new(record.Records)
	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		fmt.Println("parse error : ", val, err)
		return nil
	}

	if r.SOA == nil {
		return nil
	}

	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{Name: dns.Fqdn(zoneName), Rrtype: dns.TypeSOA,
		Class: dns.ClassINET, Ttl: uint32(r.SOA.Ttl)}
	soa.Ns = r.SOA.MName
	soa.Mbox = r.SOA.RName
	soa.Serial = r.SOA.Serial
	soa.Refresh = r.SOA.Refresh
	soa.Retry = r.SOA.Retry
	soa.Expire = r.SOA.Expire
	soa.Minttl = r.SOA.MinTtl
	if soa.Serial == 0 {
		soa.Serial = record.DefaultSerial()
	}
	return soa
}

func fromRRToRecords(zoneName string, rrs []dns.RR) map[string]record.Records {
	recordMap := make(map[string]record.Records)
	for _, rr := range rrs {
		var location string
		name := rr.Header().Name
		if dns.Fqdn(name) == dns.Fqdn(zoneName) {
			location = "@"
		} else {
			location = strings.Split(name, ".")[0]
		}
		switch rrt := rr.Header().Rrtype; rrt {
		case dns.TypeSOA:
			soa := rr.(*dns.SOA)
			soaR := &record.SOA{
				Ttl:     int(soa.Header().Ttl),
				MName:   soa.Ns,
				RName:   soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				MinTtl:  soa.Minttl,
			}
			if recs, ok := recordMap["@"]; ok {
				recs.SOA = soaR
			}
			recordMap["@"] = record.Records{SOA: soaR}
		case dns.TypeA:
			a := rr.(*dns.A)
			aR := record.A{
				Ttl: int(a.Header().Ttl),
				Ip:  a.A.To4(),
			}
			if recs, ok := recordMap[location]; ok {
				recs.A = append(recs.A, aR)
			}
			recordMap[location] = record.Records{A: []record.A{aR}}
		case dns.TypeAAAA:
			aaaa := rr.(*dns.AAAA)
			aaaaR := record.AAAA{
				Ttl: int(aaaa.Header().Ttl),
				Ip:  aaaa.AAAA.To16(),
			}
			if recs, ok := recordMap[location]; ok {
				recs.AAAA = append(recs.AAAA, aaaaR)
			}
			recordMap[location] = record.Records{AAAA: []record.AAAA{aaaaR}}
		case dns.TypeTXT:
			txt := rr.(*dns.TXT)
			txtR := record.TXT{
				Ttl:  int(txt.Header().Ttl),
				Text: strings.Join(txt.Txt, " "),
			}
			if recs, ok := recordMap[location]; ok {
				recs.TXT = append(recs.TXT, txtR)
			}
			recordMap[location] = record.Records{TXT: []record.TXT{txtR}}
		case dns.TypeCNAME:
			cname := rr.(*dns.CNAME)
			cnameR := record.CNAME{
				Ttl:  int(cname.Header().Ttl),
				Host: cname.Target,
			}
			if recs, ok := recordMap[location]; ok {
				recs.CNAME = append(recs.CNAME, cnameR)
			}
			recordMap[location] = record.Records{CNAME: []record.CNAME{cnameR}}
		case dns.TypeNS:
			ns := rr.(*dns.NS)
			nsR := record.NS{
				Ttl:  int(ns.Header().Ttl),
				Host: ns.Ns,
			}
			if recs, ok := recordMap[location]; ok {
				recs.NS = append(recs.NS, nsR)
			}
			recordMap[location] = record.Records{NS: []record.NS{nsR}}
		case dns.TypeMX:
			mx := rr.(*dns.MX)
			mxR := record.MX{
				Ttl:        int(mx.Header().Ttl),
				Host:       mx.Mx,
				Preference: mx.Preference,
			}
			if recs, ok := recordMap[location]; ok {
				recs.MX = append(recs.MX, mxR)
			}
			recordMap[location] = record.Records{MX: []record.MX{mxR}}
		case dns.TypeSRV:
			srv := rr.(*dns.SRV)
			srvR := record.SRV{
				Ttl:      int(srv.Header().Ttl),
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			}
			if recs, ok := recordMap[location]; ok {
				recs.SRV = append(recs.SRV, srvR)
			}
			recordMap[location] = record.Records{SRV: []record.SRV{srvR}}
		case dns.TypePTR:
			ptr := rr.(*dns.PTR)
			ptrR := record.PTR{
				Ttl:  int(ptr.Header().Ttl),
				Name: ptr.Ptr,
			}
			if recs, ok := recordMap[location]; ok {
				recs.PTR = append(recs.PTR, ptrR)
			}
			recordMap[location] = record.Records{PTR: []record.PTR{ptrR}}
		case dns.TypeCAA:
			caa := rr.(*dns.CAA)
			caaR := record.CAA{
				Ttl:   int(caa.Header().Ttl),
				Flag:  caa.Flag,
				Tag:   caa.Tag,
				Value: caa.Value,
			}
			if recs, ok := recordMap[location]; ok {
				recs.CAA = append(recs.CAA, caaR)
			}
			recordMap[location] = record.Records{CAA: []record.CAA{caaR}}
		}
	}
	return recordMap
}
