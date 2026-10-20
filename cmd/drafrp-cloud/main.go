package main

import (
	"context"
	"drafrp/internal/cloud"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfgPath := flag.String("config", "", "JSON config path")
	flag.Parse()
	var c cloud.Config
	if *cfgPath != "" {
		b, e := os.ReadFile(*cfgPath)
		if e != nil {
			log.Fatal(e)
		}
		if e = json.Unmarshal(b, &c); e != nil {
			log.Fatal(e)
		}
	}
	c.Listen = os.Getenv("DRAFRP_LISTEN")
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
	srv := &http.Server{Addr: c.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * 1e9, ReadTimeout: 30 * 1e9, WriteTimeout: 30 * 1e9, IdleTimeout: 120 * 1e9}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	log.Printf("drafrp-cloud listening on %s", c.Listen)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
