package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
)

func main() {
	tlsCert, err := tls.LoadX509KeyPair("/opt/homebrew/etc/mitm/cert.pem", "/opt/homebrew/etc/mitm/key.pem")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	mitmConfig.SetValidity(time.Hour * 24 * 365)
	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 2086,
		},
		MITMConfig: mitmConfig,
	})
	if err := proxy.Start(); err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}

func OnConnect() func(session *gomitmproxy.Session, proto, addr string) net.Conn {
	file, err := os.Open("/opt/homebrew/etc/mitm/hosts")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	hostMap := map[string]string{}
	wildcardMap := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		if strings.HasPrefix(str, "#") || len(str) == 0 {
			continue
		}
		items := strings.Split(str, " ")
		if len(items) != 2 {
			log.Error("invalid record: %s", str)
			continue
		}
		ip := items[0]
		domain := items[1]
		fileds := strings.Split(domain, ".")
		if len(fileds) < 2 {
			log.Error("invalid domain: %s", domain)
			continue
		}
		if fileds[0] == "*" {
			suffix := strings.Join(fileds[1:], ".")
			wildcardMap[suffix] = ip
			log.Info("add suffix domain: %s -> %s", domain, ip)
		} else {
			hostMap[domain] = ip
			log.Info("add full domain: %s -> %s", domain, ip)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	const dialTimeout = 15 * time.Second
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialTimeout,
	}
	return func(session *gomitmproxy.Session, proto, addr string) net.Conn {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			log.Error("invalid addr: %s", addr)
			return nil
		}
		if net.ParseIP(host) != nil {
			return nil
		}
		var dstHost string
		if v, ok := hostMap[host]; ok {
			dstHost = v
		} else {
			for k, v := range wildcardMap {
				if strings.HasSuffix(host, k) {
					dstHost = v
					break
				}
			}
		}
		if len(dstHost) == 0 {
			return nil
		}
		dstAddr := net.JoinHostPort(dstHost, port)
		log.Println(addr, " >>>> ", dstAddr)
		dst, err := dialer.Dial(proto, dstAddr)
		if err != nil {
			log.Error("dial custom addr: %s", err)
			return nil
		}
		return dst
	}
}
