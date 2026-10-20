package main

import (
	"context"
	"drafrp/internal/buildinfo"
	"drafrp/internal/client"
	"drafrp/internal/config"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var path string
	var version bool
	flag.StringVar(&path, "config", "client.json", "JSON configuration file")
	flag.BoolVar(&version, "version", false, "print build version")
	flag.Parse()
	if version {
		log.Print(buildinfo.String())
		return
	}
	var cfg client.Config
	if err := config.Read(path, &cfg); err != nil {
		log.Fatal(err)
	}
	a, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if !a.Bound() {
		br, err := a.Bind(ctx)
		if err != nil {
			log.Print(err)
			return
		}
		log.Printf("Approve this device: %s  user code: %s", br.VerificationURI, br.UserCode)
		log.Printf("Public key fingerprint: %s", a.PublicKeyFingerprint())
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for !a.Bound() {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if time.Now().After(br.ExpiresAt) {
				log.Print("binding expired; restart to request a new code")
				return
			}
			polled, err := a.PollBind(ctx, br.ID, br.PollToken)
			if err != nil {
				log.Printf("binding: %v", err)
				continue
			}
			if polled.Status == "expired" || polled.Status == "denied" {
				log.Printf("binding %s", polled.Status)
				return
			}
		}
	}
	interval := cfg.SyncInterval
	if interval <= 0 {
		interval = 20 * time.Second
	}
	// A failed edge cannot postpone cloud authorization renewal.
	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := a.Sync(ctx); err != nil && ctx.Err() == nil {
				log.Printf("cloud sync: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.Close()
			<-syncDone
			return
		case <-ticker.C:
		}
		for _, edge := range a.Snapshot().Edges {
			if err := a.ConnectEdge(ctx, edge); err != nil && ctx.Err() == nil {
				log.Printf("edge %s: %v", edge.ID, err)
			}
		}
	}
}
