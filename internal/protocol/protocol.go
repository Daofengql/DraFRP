// Package protocol implements DraFRP's authenticated, bounded carrier protocol.
package protocol

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "encoding/binary"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "strconv"
 "sync"
 "sync/atomic"
 "time"

 "drafrp/internal/model"
 "github.com/hashicorp/yamux"
 "github.com/quic-go/quic-go"
)

const ALPN = "drafrp/1"
const MaxFrame = 64 << 10
const MaxPacket = 65507

type Stream interface { io.ReadWriteCloser; SetDeadline(time.Time) error }
type Challenge struct { Version int `json:"version"`; Nonce string `json:"nonce"`; EdgeID string `json:"edge_id"` }
type Proof struct { DeviceID string `json:"device_id"`; SessionID string `json:"session_id"`; Generation uint64 `json:"generation"`; ExpiresAt time.Time `json:"expires_at"`; Signature string `json:"signature"` }
type Result struct { Code string `json:"code,omitempty"`; Error string `json:"error,omitempty"` }
type Flow struct { RuleID string `json:"rule_id"`; Version uint64 `json:"version"`; ID uint64 `json:"id"`; Protocol string `json:"protocol"`; Peer string `json:"peer"`; Host string `json:"host,omitempty"`; Scheme string `json:"scheme,omitempty"`; Generation uint64 `json:"generation"` }

func ID() string { b:=make([]byte,16); if _,err:=rand.Read(b);err!=nil { panic(err) }; return fmt.Sprintf("%x",b) }
func FlowID() uint64 { b:=make([]byte,8); _,_ = rand.Read(b);return binary.BigEndian.Uint64(b) }
func WriteJSON(w io.Writer, v any) error { b,err:=json.Marshal(v);if err!=nil{return err};if len(b)>MaxFrame{return errors.New("frame too large")};var n [4]byte;binary.BigEndian.PutUint32(n[:],uint32(len(b)));if _,err=w.Write(n[:]);err!=nil{return err};_,err=w.Write(b);return err }
func ReadJSON(r io.Reader,v any) error { var n [4]byte;if _,err:=io.ReadFull(r,n[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(n[:]);if size==0 || size>MaxFrame{return errors.New("invalid frame size")};b:=make([]byte,size);if _,err:=io.ReadFull(r,b);err!=nil{return err};return json.Unmarshal(b,v) }
func WritePacket(w io.Writer,b []byte) error {if len(b)>MaxPacket{return errors.New("UDP packet too large")};var h [2]byte;binary.BigEndian.PutUint16(h[:],uint16(len(b)));if _,e:=w.Write(h[:]);e!=nil{return e};_,e:=w.Write(b);return e}
func ReadPacket(r io.Reader)([]byte,error){var h [2]byte;if _,e:=io.ReadFull(r,h[:]);e!=nil{return nil,e};n:=int(binary.BigEndian.Uint16(h[:]));if n>MaxPacket{return nil,errors.New("UDP packet too large")};b:=make([]byte,n);_,e:=io.ReadFull(r,b);return b,e}
func ProofPayload(ch Challenge,p Proof) []byte {return []byte("drafrp-carrier-v1\n"+ch.EdgeID+"\n"+ch.Nonce+"\n"+p.DeviceID+"\n"+p.SessionID+"\n"+strconv.FormatUint(p.Generation,10)+"\n"+p.ExpiresAt.UTC().Format(time.RFC3339Nano))}
func AuthenticateClient(ctx context.Context,c *Carrier,d model.DeviceGrant,key ed25519.PrivateKey)error{s,e:=c.Open(ctx);if e!=nil{return e};defer s.Close();_ = s.SetDeadline(time.Now().Add(10*time.Second));var ch Challenge;if e=ReadJSON(s,&ch);e!=nil{return e};if ch.Version!=model.ProtocolVersion || ch.EdgeID!=c.EdgeID || len(ch.Nonce)!=32{return errors.New("unexpected edge identity or protocol")};p:=Proof{DeviceID:d.DeviceID,SessionID:d.SessionID,Generation:d.Generation,ExpiresAt:d.ExpiresAt};p.Signature=base64.StdEncoding.EncodeToString(ed25519.Sign(key,ProofPayload(ch,p)));if e=WriteJSON(s,p);e!=nil{return e};var result Result;if e=ReadJSON(s,&result);e!=nil{return e};if result.Error!=""{return fmt.Errorf("edge admission %s: %s",result.Code,result.Error)};c.Device=d;return nil}
func AuthenticateEdge(ctx context.Context,c *Carrier,lookup func(string)(model.DeviceGrant,bool))error{s,e:=c.Accept(ctx);if e!=nil{return e};defer s.Close();_=s.SetDeadline(time.Now().Add(10*time.Second));ch:=Challenge{Version:1,Nonce:ID(),EdgeID:c.EdgeID};if e=WriteJSON(s,ch);e!=nil{return e};var p Proof;if e=ReadJSON(s,&p);e!=nil{return e};d,ok:=lookup(p.DeviceID);pub,e:=base64.StdEncoding.DecodeString(d.PublicKey);sig,se:=base64.StdEncoding.DecodeString(p.Signature);if !ok || e!=nil || se!=nil || len(pub)!=ed25519.PublicKeySize || d.DeviceID!=p.DeviceID || d.SessionID!=p.SessionID || d.Generation!=p.Generation || !d.ExpiresAt.Equal(p.ExpiresAt) || !time.Now().Before(d.ExpiresAt) || !ed25519.Verify(ed25519.PublicKey(pub),ProofPayload(ch,p),sig){_ = WriteJSON(s,Result{Code:"unauthorized",Error:"device grant or proof invalid"});return errors.New("invalid device admission")};c.Device=d;return WriteJSON(s,Result{})}

type assembly struct{ parts [][]byte; total int; received int; bytes int; expires time.Time }
type Carrier struct {
 EdgeID string
 Device model.DeviceGrant
 Transport string
 q *quic.Conn
 mux *yamux.Session
 closed chan struct{}
 once sync.Once
 active atomic.Int64
 msg atomic.Uint32
 mu sync.Mutex
 packets map[uint64]chan []byte
 pending map[[2]uint64]*assembly
 pendingBytes int
}
func WrapQUIC(q *quic.Conn,edgeID string)*Carrier{c:=&Carrier{q:q,EdgeID:edgeID,Transport:"quic",closed:make(chan struct{}),packets:map[uint64]chan []byte{},pending:map[[2]uint64]*assembly{}};go c.receive();return c}
func WrapTLS(conn net.Conn,server bool,edgeID string)(*Carrier,error){cfg:=yamux.DefaultConfig();cfg.AcceptBacklog=64;cfg.MaxStreamWindowSize=256<<10;cfg.StreamOpenTimeout=10*time.Second;cfg.StreamCloseTimeout=15*time.Second;cfg.ConnectionWriteTimeout=10*time.Second;cfg.LogOutput=io.Discard;var m *yamux.Session;var e error;if server{m,e=yamux.Server(conn,cfg)}else{m,e=yamux.Client(conn,cfg)};if e!=nil{return nil,e};return &Carrier{mux:m,EdgeID:edgeID,Transport:"tls",closed:make(chan struct{})},nil}
func(c *Carrier) Open(ctx context.Context)(Stream,error){if c.q!=nil{return c.q.OpenStreamSync(ctx)};return c.mux.OpenStream()}
func(c *Carrier) Accept(ctx context.Context)(Stream,error){if c.q!=nil{return c.q.AcceptStream(ctx)};return c.mux.AcceptStream()}
func(c *Carrier) Close()error{c.once.Do(func(){close(c.closed);if c.q!=nil{_=c.q.CloseWithError(0,"closed")}else{_=c.mux.Close()}});return nil}
func(c *Carrier) Done()<-chan struct{}{if c.q!=nil{return c.q.Context().Done()};return c.mux.CloseChan()}
func(c *Carrier) Datagram()bool{return c.q!=nil && c.q.ConnectionState().SupportsDatagrams}
func(c *Carrier) Active()int64{return c.active.Load()}
func(c *Carrier) AddActive(delta int64){c.active.Add(delta)}
func(c *Carrier) Register(id uint64)(<-chan []byte,func(),error){c.mu.Lock();defer c.mu.Unlock();if len(c.packets)>=128{return nil,nil,errors.New("UDP flow capacity")};if _,ok:=c.packets[id];ok{return nil,nil,errors.New("duplicate UDP flow")};ch:=make(chan []byte,8);c.packets[id]=ch;return ch,func(){c.mu.Lock();delete(c.packets,id);for k,a:=range c.pending{if k[0]==id{c.pendingBytes-=a.bytes;delete(c.pending,k)}};c.mu.Unlock()},nil}
func(c *Carrier) SendPacket(id uint64,b []byte)error{if len(b)>MaxPacket{return errors.New("UDP packet too large")};seq:=c.msg.Add(1);count:=(len(b)+999)/1000;if count==0{count=1};for i:=0;i<count;i++{end:=min((i+1)*1000,len(b));p:=make([]byte,18+end-i*1000);binary.BigEndian.PutUint64(p[0:8],id);binary.BigEndian.PutUint32(p[8:12],seq);binary.BigEndian.PutUint16(p[12:14],uint16(i));binary.BigEndian.PutUint16(p[14:16],uint16(count));binary.BigEndian.PutUint16(p[16:18],uint16(len(b)));copy(p[18:],b[i*1000:end]);if e:=c.q.SendDatagram(p);e!=nil{return e}};return nil}
func(c *Carrier) receive(){for{p,e:=c.q.ReceiveDatagram(context.Background());if e!=nil{return};if len(p)<18{continue};id:=binary.BigEndian.Uint64(p[:8]);seq:=binary.BigEndian.Uint32(p[8:12]);part:=int(binary.BigEndian.Uint16(p[12:14]));count:=int(binary.BigEndian.Uint16(p[14:16]));total:=int(binary.BigEndian.Uint16(p[16:18]));if count<1 || count>66 || part>=count || total>MaxPacket || count!=max(1,(total+999)/1000) || len(p)-18!=min(1000,total-part*1000){continue};c.mu.Lock();ch,ok:=c.packets[id];if !ok{c.mu.Unlock();continue};now:=time.Now();for k,a:=range c.pending{if now.After(a.expires){c.pendingBytes-=a.bytes;delete(c.pending,k)}};k:=[2]uint64{id,uint64(seq)};a:=c.pending[k];if a==nil{if len(c.pending)>=128 || c.pendingBytes+total>4<<20{c.mu.Unlock();continue};a=&assembly{parts:make([][]byte,count),total:total,expires:now.Add(2*time.Second)};c.pending[k]=a};if a.total!=total || len(a.parts)!=count || a.parts[part]!=nil{c.mu.Unlock();continue};a.parts[part]=append([]byte{},p[18:]...);a.received++;a.bytes+=len(p)-18;c.pendingBytes+=len(p)-18;if a.received==count{b:=make([]byte,0,total);for _,v:=range a.parts{b=append(b,v...)};delete(c.pending,k);c.pendingBytes-=a.bytes;select{case ch<-b:default:}};c.mu.Unlock()}}

func TLSClient(caFile,caPEM,serverName string)(*tls.Config,error){roots,e:=x509.SystemCertPool();if e!=nil{roots=x509.NewCertPool()};if caFile!=""{b,e:=os.ReadFile(caFile);if e!=nil{return nil,e};if !roots.AppendCertsFromPEM(b){return nil,errors.New("invalid CA file")}};if caPEM!=""&&!roots.AppendCertsFromPEM([]byte(caPEM)){return nil,errors.New("invalid edge CA")};return &tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots,ServerName:serverName,NextProtos:[]string{ALPN}},nil}
func HTTPClient(caFile string)(*http.Client,error){cfg,e:=TLSClient(caFile,"","");if e!=nil{return nil,e};cfg.NextProtos=[]string{"h2","http/1.1"};return &http.Client{Timeout:20*time.Second,Transport:&http.Transport{TLSClientConfig:cfg,Proxy:http.ProxyFromEnvironment,MaxIdleConns:8,IdleConnTimeout:30*time.Second}},nil}
func QUICConfig()*quic.Config{return &quic.Config{EnableDatagrams:true,MaxIncomingStreams:128,MaxIncomingUniStreams:0,HandshakeIdleTimeout:5*time.Second,MaxIdleTimeout:45*time.Second,KeepAlivePeriod:15*time.Second,InitialStreamReceiveWindow:64<<10,MaxStreamReceiveWindow:256<<10,InitialConnectionReceiveWindow:512<<10,MaxConnectionReceiveWindow:4<<20,Allow0RTT:false}}
// Abort closes both directions of QUIC streams; Close alone is only a write FIN.
func Abort(s Stream){if q,ok:=s.(*quic.Stream);ok{q.CancelRead(0);q.CancelWrite(0)};_ = s.Close()}
func HalfClose(w io.Writer){if q,ok:=w.(*quic.Stream);ok{_=q.Close();return};if h,ok:=w.(interface{CloseWrite()error});ok{_=h.CloseWrite();return};if h,ok:=w.(interface{Close()error});ok{_=h.Close()}}
