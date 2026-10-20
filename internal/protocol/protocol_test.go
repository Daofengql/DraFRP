package protocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"drafrp/internal/model"
)

func tlsPair(t *testing.T) (*Carrier, *Carrier) {
	t.Helper()
	a, b := net.Pipe()
	x, err := WrapTLS(a, false, "edge")
	if err != nil {
		t.Fatal(err)
	}
	y, err := WrapTLS(b, true, "edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close(); _ = y.Close() })
	return x, y
}
func TestAdmissionBindsIdentitySessionAndRenewableLease(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewed_lease", true: "wrong_session"}[bad], func(t *testing.T) {
			x, y := tlsPair(t)
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			d := model.DeviceGrant{DeviceID: "device", TenantID: "tenant", PublicKey: base64.StdEncoding.EncodeToString(pub), SessionID: "session", Generation: 3, ExpiresAt: time.Now().Add(time.Minute)}
			proof := d
			proof.ExpiresAt = time.Now().Add(10 * time.Second)
			if bad {
				proof.SessionID = "other-session"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- AuthenticateEdge(ctx, y, func(id string) (model.DeviceGrant, bool) { return d, id == d.DeviceID })
			}()
			err := AuthenticateClient(ctx, x, proof, key)
			if (err != nil) != bad {
				t.Fatalf("admission error %v, wrong session=%v", err, bad)
			}
			if e := <-done; (e != nil) != bad {
				t.Fatalf("edge result %v", e)
			}
		})
	}
}
func TestAbortYamuxReadDoesNotCloseOtherStreams(t *testing.T) {
	x, y := tlsPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a, err := x.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := y.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { var p [1]byte; _, err := b.Read(p[:]); done <- err }()
	Abort(b)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aborted read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("aborted yamux read remained blocked")
	}
	Finish(a)
	c, err := x.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d, err := y.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = WriteFull(c, []byte("alive")); Finish(c) }()
	got, err := io.ReadAll(d)
	if err != nil || string(got) != "alive" {
		t.Fatalf("unrelated flow %q %v", got, err)
	}
	Finish(d)
	cc, stop := context.WithCancel(ctx)
	stop()
	start := time.Now()
	if _, err = y.Accept(cc); err == nil || time.Since(start) > time.Second {
		t.Fatal("Accept ignored cancellation")
	}
}

func packet(id uint64, seq uint32, part, total int) []byte {
	count := max(1, (total+999)/1000)
	size := min(1000, total-part*1000)
	p := make([]byte, 18+size)
	binary.BigEndian.PutUint64(p, id)
	binary.BigEndian.PutUint32(p[8:], seq)
	binary.BigEndian.PutUint16(p[12:], uint16(part))
	binary.BigEndian.PutUint16(p[14:], uint16(count))
	binary.BigEndian.PutUint16(p[16:], uint16(total))
	for i := 18; i < len(p); i++ {
		p[i] = byte((part*1000 + i - 18) % 251)
	}
	return p
}
func receiver() (*Carrier, chan []byte) {
	ch := make(chan []byte, 8)
	return &Carrier{packets: map[uint64]chan []byte{1: ch}, pending: map[[2]uint64]*assembly{}, replays: map[uint64]*replayWindow{1: {}}}, ch
}
func TestDatagramReassemblyReorderingReplayAndExpiry(t *testing.T) {
	c, ch := receiver()
	now := time.Now()
	total := MaxPacket
	count := (total + 999) / 1000
	for i := count - 1; i >= 0; i-- {
		p := packet(1, 8, i, total)
		c.handleDatagram(p, now)
		c.handleDatagram(p, now)
	}
	select {
	case got := <-ch:
		want := make([]byte, total)
		for i := range want {
			want[i] = byte(i % 251)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("fragment order or contents changed")
		}
	default:
		t.Fatal("large datagram was not reassembled")
	}
	for i := 0; i < count; i++ {
		c.handleDatagram(packet(1, 8, i, total), now)
	}
	select {
	case <-ch:
		t.Fatal("duplicate datagram delivered")
	default:
	}
	c.handleDatagram(packet(1, 7, 0, 1), now)
	if len(<-ch) != 1 {
		t.Fatal("reasonable sequence reordering rejected")
	}
	c.handleDatagram(packet(1, 9, 0, 2000), now)
	c.handleDatagram(packet(1, 10, 0, 1), now.Add(3*time.Second))
	<-ch
	c.handleDatagram(packet(1, 9, 1, 2000), now.Add(3*time.Second))
	select {
	case <-ch:
		t.Fatal("expired message revived")
	default:
	}
	if c.pendingBytes != 0 || len(c.pending) != 0 {
		t.Fatalf("expired reservation retained: %d %d", c.pendingBytes, len(c.pending))
	}
}
func TestDatagramReservationCannotExceedMemoryBudget(t *testing.T) {
	c, _ := receiver()
	now := time.Now()
	for seq := uint32(1); seq <= 100; seq++ {
		c.handleDatagram(packet(1, seq, 0, MaxPacket), now)
	}
	if c.pendingBytes > 4<<20 || len(c.pending) > 64 {
		t.Fatalf("reservation budget exceeded: %d bytes %d messages", c.pendingBytes, len(c.pending))
	}
	for key := range c.pending {
		for part := 1; part < 66; part++ {
			c.handleDatagram(packet(1, uint32(key[1]), part, MaxPacket), now)
		}
	}
	if c.pendingBytes != 0 || len(c.pending) != 0 {
		t.Fatal("completed reservations leaked")
	}
	c.handleDatagram(packet(2, 500, 0, 2), now)
	if len(c.pending) != 0 {
		t.Fatal("unknown flow created target mapping")
	}
}
func TestReplaySequenceWindowWrapAndLargeGap(t *testing.T) {
	var w replayWindow
	for _, seq := range []uint32{0xfffffffe, 0xffffffff, 0, 2, 1, 90, 64, 3000, 2999} {
		if w.seen(seq) {
			t.Fatalf("new sequence %d rejected", seq)
		}
		w.mark(seq)
		if !w.seen(seq) {
			t.Fatalf("sequence %d not remembered", seq)
		}
	}
	if !w.seen(90) {
		t.Fatal("message older than window accepted")
	}
}
