package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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
