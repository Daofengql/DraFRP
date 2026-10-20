// Package acl compiles only administrator-supplied TCP/UDP policies.
package acl

import (
 "errors"
 "fmt"
 "net/netip"
 "sort"
 "drafrp/internal/model"
)
type entry struct{model.ACLEntry; prefixes []netip.Prefix}
type Policy struct{defaultAction string; entries []entry}
func Compile(p model.ACLPolicy)(*Policy,error){if p.DefaultAction!="allow"&&p.DefaultAction!="deny"{return nil,errors.New("ACL requires explicit default_action")};out:=&Policy{defaultAction:p.DefaultAction};priorities:=map[int]bool{};for _,e:=range p.Entries{if e.Action!="allow"&&e.Action!="deny"{return nil,errors.New("invalid ACL action")};if e.Protocol!=""&&e.Protocol!="tcp"&&e.Protocol!="udp"{return nil,errors.New("invalid ACL protocol")};if priorities[e.Priority]{return nil,errors.New("duplicate ACL priority")};priorities[e.Priority]=true;ce:=entry{ACLEntry:e};for _,s:=range e.CIDRs{p,err:=netip.ParsePrefix(s);if err!=nil{return nil,fmt.Errorf("ACL CIDR: %w",err)};ce.prefixes=append(ce.prefixes,p.Masked())};for _,port:=range e.Ports{if port<1||port>65535{return nil,errors.New("invalid ACL port")}};out.entries=append(out.entries,ce)};sort.Slice(out.entries,func(i,j int)bool{return out.entries[i].Priority<out.entries[j].Priority});return out,nil}
func(p *Policy)Allow(ip netip.Addr,proto string,port int)(bool,string){ip=ip.Unmap();for _,e:=range p.entries{if e.Protocol!=""&&e.Protocol!=proto{continue};if len(e.Ports)>0{found:=false;for _,v:=range e.Ports{found=found||v==port};if !found{continue}};if len(e.prefixes)>0{found:=false;for _,v:=range e.prefixes{found=found||v.Contains(ip)};if !found{continue}};return e.Action=="allow",e.ID};return p.defaultAction=="allow","default"}
