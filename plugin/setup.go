package plugin

import (
	"errors"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/yoeluk/coredns-redis-backend"
)

func init() {
	caddy.RegisterPlugin("redis", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	r, err := redisParse(c)
	if err != nil {
		return err
	}

	if ok, err := r.Ping(); err != nil || !ok {
		return plugin.Error("redis", err)
	} else if ok {
		log.Infof("ping to redis ok")
	}

	p := &Plugin{
		Redis:          r,
		loadZoneTicker: time.NewTicker(time.Duration(r.DefaultTtl) * time.Second),
	}
	// p.startZoneNameCache()

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}

func redisParse(c *caddy.Controller) (*redis.Redis, error) {
	r := redis.New()

	for c.Next() {
		if c.NextBlock() {
			for {
				switch c.Val() {
				case "address":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetAddress(c.Val())
				case "username":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetUsername(c.Val())
				case "password":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetPassword(c.Val())
				case "prefix":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetKeyPrefix(c.Val())
				case "suffix":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetKeySuffix(c.Val())
				case "connect_timeout":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err == nil {
						r.SetConnectTimeout(t)
					}
				case "read_timeout":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						r.SetReadTimeout(t)
					}
				case "ttl":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						r.SetDefaultTtl(redis.DefaultTtl)
					} else {
						r.SetDefaultTtl(t)
					}
				case "referral_prefix":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetReferralPrefix(c.Val())
				case "root_host":
					if !c.NextArg() {
						return r, c.ArgErr()
					}
					r.SetRootHost(c.Val())
				default:
					if c.Val() != "}" {
						return r, c.Errf("unknown property '%s'", c.Val())
					}
				}

				if !c.Next() {
					break
				}
			}

		}

		err := r.Connect()
		return r, err
	}

	return nil, errors.New("no configuration found")
}
