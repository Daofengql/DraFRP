package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"drafrp/internal/client"
)

func main() {
	var path string
	flag.StringVar(&path,"config","client.json","JSON configuration file"); flag.Parse()
	b,e:=os.ReadFile(path);if e!=nil{log.Fatal(e)};var cfg client.Config;if e=json.Unmarshal(b,&cfg);e!=nil{log.Fatal(e)}
	a,e:=client.New(cfg);if e!=nil{log.Fatal(e)};defer a.Close();ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer cancel()
	if cfg.Bind || cfg.BindCode!="" { br,e:=a.Bind(ctx);if e!=nil{log.Fatal(e)};log.Printf("binding id=%s user_code=%s verification_uri=%s",br.ID,br.UserCode,br.VerificationURI);for {if cfg.BindCode!="" {break};select{case<-ctx.Done():return;case<-time.After(2*time.Second):};br,e=a.PollBind(ctx,br.ID,br.PollToken);if e!=nil{log.Printf("bind poll: %v",e);continue};if br.Status=="approved"{break};if br.Status=="expired"{log.Fatal("binding expired")}};if cfg.BindCode!=""{for{br,e=a.PollBind(ctx,br.ID,cfg.PollToken);if e==nil&&br.Status=="approved"{break};select{case<-ctx.Done():return;case<-time.After(2*time.Second):}}}}
	if _,e=a.Sync(ctx);e!=nil{log.Fatal(e)}
	for{snap:=a.Snapshot();for _,e:=range snap.Edges{if _,ok:=current(a,e.ID);!ok{if er:=a.ConnectEdge(ctx,e);er!=nil{log.Printf("edge %s: %v",e.ID,er)}}};select{case<-ctx.Done():return;case<-time.After(cfg.SyncInterval)}}
}
func current(a *client.Agent,id string)(bool,bool){return false,false}
