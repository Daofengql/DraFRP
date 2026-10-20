package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"drafrp/internal/edge"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "edge.json", "JSON configuration file")
	flag.Parse()
	b, err := os.ReadFile(configPath)
	if err != nil { log.Fatal(err) }
	var cfg edge.Config
	if err = json.Unmarshal(b, &cfg); err != nil { log.Fatal(err) }
	r := edge.New(cfg)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel(); defer r.Close()
	// Sync before opening carriers. A stale or missing snapshot must never turn
	// the edge into an unauthenticated forwarding server.
	for {
		e := r.Sync(ctx)
		if e == nil { break }
		log.Printf("cloud sync: %v", e)
		select { case <-ctx.Done(): return; case <-time.After(2*time.Second): }
	}
	go syncLoop(ctx, r, cfg.SyncInterval)
	snap := r.Snapshot()
	for _, ep := range snap.Edge.Endpoints {
		addr := listenerAddr(ep.Address, cfg.ListenHost)
		switch strings.ToLower(ep.Transport) {
		case "quic", "udp":
			ln, e := edge.ListenQUIC(cfg, addr); if e != nil { log.Printf("QUIC %s: %v", addr, e); continue }
			go func(l interface{ Accept(context.Context) (*quic.Conn,error) }) { for { q,e:=l.Accept(ctx); if e!=nil{return}; r.ServeCarrier(ctx,protocol.WrapQUIC(q,cfg.EdgeID)) } }(ln)
		case "tls", "tcp":
			cert,e:=tls.LoadX509KeyPair(cfg.CertFile,cfg.KeyFile);if e!=nil{log.Printf("TLS cert: %v",e);continue};tc:=&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13,NextProtos:[]string{protocol.ALPN}};l,e:=tls.Listen("tcp",addr,tc);if e!=nil{log.Printf("TLS %s: %v",addr,e);continue};go func(){for{conn,e:=l.Accept();if e!=nil{return};c,e:=protocol.WrapTLS(conn,true,cfg.EdgeID);if e!=nil{_ = conn.Close();continue};go r.ServeCarrier(ctx,c)}}()
		}
	}
	<-ctx.Done()
}
func syncLoop(ctx context.Context,r *edge.Runtime,d time.Duration){if d<=0{d=20*time.Second};t:=time.NewTicker(d);defer t.Stop();for{select{case<-ctx.Done():return;case<-t.C:rctx,cancel:=context.WithTimeout(ctx,10*time.Second);if e:=r.Sync(rctx);e!=nil{log.Printf("cloud sync: %v",e)};cancel()}}}
func listenerAddr(address,host string)string{if _,p,e:=net.SplitHostPort(address);e==nil&&p!=""{return net.JoinHostPort(host,p)};return address}
var _ model.Edge
