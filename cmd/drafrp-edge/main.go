package main

import (
	"context"
	"drafrp/internal/buildinfo"
	"drafrp/internal/config"
	"drafrp/internal/edge"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	path := flag.String("config", "edge.json", "JSON configuration file")
	version := flag.Bool("version", false, "print build information")
	flag.Parse()
	if *version {
		fmt.Println(buildinfo.String())
		return
	}
	if runtime.GOOS != "linux" {
		log.Fatal("drafrp-edge is supported on Linux; Windows supports the socket client only")
	}
	var cfg edge.Config
	if e := config.Read(*path, &cfg); e != nil {
		log.Fatal(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	r := edge.New(cfg)
	defer r.Close()
	log.Printf("%s; edge=%s", buildinfo.String(), cfg.EdgeID)
	if e := r.Run(ctx); e != nil {
		log.Fatal(e)
	}
}
