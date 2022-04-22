package plugin

import (
	"encoding/json"
	"fmt"
	redisCon "github.com/gomodule/redigo/redis"
	"github.com/miekg/dns"
	"github.com/yoeluk/coredns-redis-backend/record"
	"strings"
)

func (p *Plugin) Persist(zone string, rrs []dns.RR) error {
	records := fromRRToRecords(rrs)
	if records.SOA == nil {
		log.Debugf("fromRRToRecords return records without an SOA records")
		return nil
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

func fromRRToRecords(rrs []dns.RR) (records record.Records) {
	for _, rr := range rrs {
		switch rrt := rr.Header().Rrtype; rrt {
		case dns.TypeSOA:
			soa := rr.(*dns.SOA)
			records.SOA = &record.SOA{
				Ttl:     int(soa.Header().Ttl),
				MName:   soa.Ns,
				RName:   soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				MinTtl:  soa.Minttl,
			}
		case dns.TypeA:
			a := rr.(*dns.A)
			records.A = append(records.A, record.A{
				Ttl: int(a.Header().Ttl),
				Ip:  a.A.To4(),
			})
		case dns.TypeAAAA:
			aaaa := rr.(*dns.AAAA)
			records.AAAA = append(records.AAAA, record.AAAA{
				Ttl: int(aaaa.Header().Ttl),
				Ip:  aaaa.AAAA.To16(),
			})
		case dns.TypeTXT:
			tx := rr.(*dns.TXT)
			records.TXT = append(records.TXT, record.TXT{
				Ttl:  int(tx.Header().Ttl),
				Text: strings.Join(tx.Txt, " "),
			})
		case dns.TypeCNAME:
			cname := rr.(*dns.CNAME)
			records.CNAME = append(records.CNAME, record.CNAME{
				Ttl:  int(cname.Header().Ttl),
				Host: cname.Target,
			})
		case dns.TypeNS:
			ns := rr.(*dns.NS)
			records.NS = append(records.NS, record.NS{
				Ttl:  int(ns.Header().Ttl),
				Host: ns.Ns,
			})
		case dns.TypeMX:
			mx := rr.(*dns.MX)
			records.MX = append(records.MX, record.MX{
				Ttl:        int(mx.Header().Ttl),
				Host:       mx.Mx,
				Preference: mx.Preference,
			})
		case dns.TypeSRV:
			srv := rr.(*dns.SRV)
			records.SRV = append(records.SRV, record.SRV{
				Ttl:      int(srv.Header().Ttl),
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			})
		case dns.TypePTR:
			ptr := rr.(*dns.PTR)
			records.PTR = append(records.PTR, record.PTR{
				Ttl:  int(ptr.Header().Ttl),
				Name: ptr.Ptr,
			})
		case dns.TypeCAA:
			ca := rr.(*dns.CAA)
			records.CAA = append(records.CAA, record.CAA{
				Ttl:   int(ca.Header().Ttl),
				Flag:  ca.Flag,
				Tag:   ca.Tag,
				Value: ca.Value,
			})
		}
	}
	return
}
