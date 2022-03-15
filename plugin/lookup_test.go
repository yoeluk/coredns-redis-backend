package plugin

import (
	"context"
	"github.com/nvlong17/redis"
	"github.com/nvlong17/redis/record"
	"net"
)

//todo: mock redis for testing

const (
	prefix, suffix = "lookup-test_", "_lookup-test"
	defaultTtl     = 500
	testTtl        = 4242
	txt            = "Lamas, seekers, and great monkeys will always protect them."
	wcTxt          = "This is a wildcard TXT record"
)

var zones = []string{"example.net", "example.org"}

type testRecord struct {
	l string
	r record.Record
}

var testRecords = []testRecord{
	{"@", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.34")}},
	{"www", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.34")}},
	{"@", record.AAAA{Ttl: testTtl, Ip: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}},
	{"www", record.AAAA{Ttl: testTtl, Ip: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}},
	{"@", record.TXT{Ttl: testTtl, Text: txt}},
	{"@", record.NS{Ttl: testTtl, Host: "ns1.example.org."}},
	{"@", record.NS{Ttl: testTtl, Host: "ns2.example.org."}},
	{"@", record.NS{Ttl: testTtl, Host: "ns3"}},
	{"@", record.MX{Ttl: testTtl, Host: "mail.example.org.", Preference: 10}},
	{"wwx", record.CNAME{Ttl: testTtl, Host: "www.example.org."}},
	{"wxx", record.CNAME{Ttl: testTtl, Host: "wwx.example.org."}},
	{"_autodiscover._tcp", record.SRV{Ttl: testTtl, Priority: 10, Weight: 50, Port: 443, Target: "mail.example.org."}},
	{"ns1", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.36")}},
	{"ns2", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.37")}},
	{"mail", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.38")}},
	{"mail", record.AAAA{Ttl: testTtl, Ip: net.ParseIP("2606:2800:220:1:248:1893:25c8:1947")}},
	{"@", record.CAA{Ttl: testTtl, Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
	{"lb", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.39")}},
	{"lb", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.40")}},
	{"lb", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.41")}},
	{"lb", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.42")}},
	{"*", record.A{Ttl: testTtl, Ip: net.ParseIP("93.184.216.43")}},
	{"*", record.TXT{Ttl: testTtl, Text: wcTxt}},
}

func newRedisPlugin() (*Plugin, error) {
	ctxt = context.TODO()

	p := new(Plugin)
	p.Redis = redis.New()
	p.Redis.SetDefaultTtl(defaultTtl)
	p.Redis.SetKeyPrefix("__CUST1:")
	p.Redis.SetReferralPrefix("referral:")
	//p.Redis.SetPassword("iAkUmLqq0u")
	p.Redis.SetPassword("FADCMe49wP")
	p.Redis.SetAddress("127.0.0.1:6379")
	err := p.Redis.Connect()
	return p, err
}

var ctxt context.Context
