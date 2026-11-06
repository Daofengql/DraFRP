package main

import (
	"context"
	"drafrp/internal/buildinfo"
	"drafrp/internal/cloud"
	"drafrp/internal/config"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "", "JSON config path")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		log.Print(buildinfo.String())
		return
	}
	var c cloud.Config
	if *cfgPath != "" {
		if e := config.Read(*cfgPath, &c); e != nil {
			log.Fatal(e)
		}
	}
	if c.BuildID == "" {
		c.BuildID = buildinfo.ID()
	}
	if v := os.Getenv("DRAFRP_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("DRAFRP_SECURE_COOKIES"); v != "" {
		secure, err := strconv.ParseBool(v)
		if err != nil {
			log.Fatalf("invalid DRAFRP_SECURE_COOKIES: %v", err)
		}
		c.SecureCookies = secure
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, e := cloud.New(ctx, c)
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	if (c.TLSCert == "") != (c.TLSKey == "") {
		log.Fatal("tls_cert and tls_key must be configured together")
	}
	srv := &http.Server{Addr: c.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("drafrp-cloud listening on %s", c.Listen)
	if c.TLSCert != "" {
		e = srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	} else {
		e = srv.ListenAndServe()
	}
	if e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
