// This file is copied from https://github.com/yinghuocho/gotun2socks/blob/master/udp.go

package cache

import (
	"time"

	"github.com/miekg/dns"

	"github.com/eycorsican/go-tun2socks/common/cache"
	cdns "github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
)

const minCleanupInterval = 5 * time.Minute

type dnsCacheEntry struct {
	msg []byte
}

type simpleDnsCache struct {
	storage *cache.Cache
}

func NewSimpleDnsCache() cdns.DnsCache {
	s := cache.New(minCleanupInterval)
	return &simpleDnsCache{
		storage: s,
	}
}

func packUint16(i uint16) []byte { return []byte{byte(i >> 8), byte(i)} }

func cacheKey(q dns.Question) string {
	return string(append([]byte(q.Name), packUint16(q.Qtype)...))
}

func (c *simpleDnsCache) Query(payload []byte) []byte {
	request := new(dns.Msg)
	e := request.Unpack(payload)
	if e != nil {
		return nil
	}
	if len(request.Question) == 0 {
		return nil
	}

	key := cacheKey(request.Question[0])
	entryInterface := c.storage.Get(key)
	if entryInterface == nil {
		return nil
	}
	entry := entryInterface.(*dnsCacheEntry)
	if entry == nil {
		return nil
	}

	resp := new(dns.Msg)
	resp.Unpack(entry.msg)
	resp.Id = request.Id
	var buf [1024]byte
	dnsAnswer, err := resp.PackBuffer(buf[:])
	if err != nil {
		return nil
	}
	log.Debugf("got dns answer from cache with key: %v", key)
	return append([]byte(nil), dnsAnswer...)
}

func (c *simpleDnsCache) Store(payload []byte) {
	resp := new(dns.Msg)
	e := resp.Unpack(payload)
	if e != nil {
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		return
	}
	if len(resp.Question) == 0 || len(resp.Answer) == 0 {
		return
	}

	key := cacheKey(resp.Question[0])
	ttl := resp.Answer[0].Header().Ttl
	value := &dnsCacheEntry{
		msg: payload,
	}
	c.storage.Put(key, value, time.Duration(ttl)*time.Second)

	log.Debugf("stored dns answer with key: %v, ttl: %v sec", key, ttl)
}
