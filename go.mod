module github.com/nvlong17/redis

go 1.13

require (
	github.com/coredns/caddy v1.1.1
	github.com/coredns/coredns v1.8.6
	github.com/gomodule/redigo v1.8.2
	github.com/miekg/dns v1.1.43
)

replace github.com/rverst/coredns-redis => github.com/nvlong17/redis v1.1.3
