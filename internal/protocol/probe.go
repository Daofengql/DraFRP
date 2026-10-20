package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"drafrp/internal/model"
	"github.com/quic-go/quic-go"
)

const ProbeInterval = 5 * time.Second
const ProbeTimeout = 2 * time.Second
const ProbeWindowLimit = 64
const probeWindowAge = ProbeInterval * ProbeWindowLimit

var probeMagic = [8]byte{'D', 'r', 'a', 'P', 'R', 'O', 'B', 1}
var errProbeUnavailable = errors.New("carrier probe unsupported, busy or cooling down")

type probeSample struct {
	started, finished time.Time
	rtt               time.Duration
	outcome           uint8 // 0 success, 1 timeout, 2 other transport/protocol error
}
type carrierProbeState struct {
	enabled                atomic.Bool
	running                atomic.Bool
	mu                     sync.Mutex
	samples                [ProbeWindowLimit]probeSample
	next, count            int
	lastAttempt, lastServe time.Time
}

func (c *Carrier) ProbeSupported() bool { return c.probe.enabled.Load() }

// ObserveQuality owns at most one request at a time, with fixed cadence, size,
// timeout and memory. Authorization refers to the current renewable snapshot,
// not the deliberately short proof used only during admission.
func (c *Carrier) ObserveQuality(ctx context.Context, authorized func() bool) {
	if !c.ProbeSupported() || authorized == nil {
		return
	}
	defer c.clearProbeSamples()
	for {
		if ctx.Err() != nil || !authorized() {
			return
		}
		_ = c.Probe(ctx)
		if !authorized() {
			return
		}
		// The interval starts when Probe actually reserves its attempt, after
		// authorization and scheduling delays. An independently phased ticker
		// can fire just before that cooldown ends and skip every other attempt.
		timer := time.NewTimer(c.nextProbeDelay(time.Now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Carrier) nextProbeDelay(at time.Time) time.Duration {
	c.probe.mu.Lock()
	last := c.probe.lastAttempt
	c.probe.mu.Unlock()
	if last.IsZero() {
		// A separately invoked Probe may have claimed the single-inflight
		// guard but not yet published its timestamp. Do not spin in that gap.
		return ProbeInterval
	}
	return max(0, last.Add(ProbeInterval).Sub(at))
}

// Probe never opens a business flow, target socket or UDP mapping, and does not
// alter Active(). The negotiated capability is published only after admission.
func (c *Carrier) Probe(ctx context.Context) error {
	if !c.ProbeSupported() || !c.probe.running.CompareAndSwap(false, true) {
		return errProbeUnavailable
	}
	defer c.probe.running.Store(false)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-c.Done():
		return net.ErrClosed
	default:
	}
	started := time.Now()
	c.probe.mu.Lock()
	if started.Sub(c.probe.lastAttempt) < ProbeInterval {
		c.probe.mu.Unlock()
		return errProbeUnavailable
	}
	c.probe.lastAttempt = started
	c.probe.mu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	err := c.exchangeProbe(probeCtx)
	if err == nil && probeCtx.Err() != nil {
		err = probeCtx.Err()
	}
	// Shutdown, revoked/expired snapshots and caller cancellation are not a
	// measurement of the network. The owner clears the window on retirement.
	if ctx.Err() != nil {
		return err
	}
	select {
	case <-c.Done():
		return err
	default:
	}
	sample := probeSample{started: started, finished: time.Now()}
	if err == nil {
		sample.rtt = sample.finished.Sub(started)
	} else {
		var timeout net.Error
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			sample.outcome = 1
		} else {
			sample.outcome = 2
		}
	}
	c.probe.mu.Lock()
	select {
	case <-c.Done():
		c.probe.mu.Unlock()
		return err
	default:
	}
	c.probe.samples[c.probe.next] = sample
	c.probe.next = (c.probe.next + 1) % ProbeWindowLimit
	c.probe.count = min(c.probe.count+1, ProbeWindowLimit)
	c.probe.mu.Unlock()
	return err
}

func (c *Carrier) exchangeProbe(ctx context.Context) error {
	var request [24]byte
	copy(request[:8], probeMagic[:])
	if _, err := rand.Read(request[8:]); err != nil {
		return err
	}
	stream, err := c.Open(ctx)
	if err != nil {
		return err
	}
	defer Abort(stream)
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { Abort(stream) })
	defer stop()
	if err = WriteFull(stream, request[:]); err != nil {
		return err
	}
	var response [24]byte
	if _, err = io.ReadFull(stream, response[:]); err != nil {
		return err
	}
	if response != request {
		return errors.New("invalid carrier probe echo")
	}
	return nil
}

// HandleProbe accepts only the fixed authenticated control echo. The edge calls
// it synchronously from its per-carrier accept loop: one incoming probe can be
// pending, at most once a second, and never consumes a business flow permit.
// In particular, JSON Flow messages on Agent-initiated streams stay rejected.
func (c *Carrier) HandleProbe(ctx context.Context, stream Stream, authorized func() bool) {
	finished := false
	defer func() {
		if finished {
			Finish(stream)
		} else {
			Abort(stream)
		}
	}()
	if !c.ProbeSupported() || authorized == nil || ctx.Err() != nil || !authorized() {
		return
	}
	at := time.Now()
	c.probe.mu.Lock()
	limited := at.Sub(c.probe.lastServe) < time.Second
	if !limited {
		c.probe.lastServe = at
	}
	c.probe.mu.Unlock()
	if limited {
		return
	}
	deadline := at.Add(ProbeTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { Abort(stream) })
	defer stop()
	var request [24]byte
	if _, err := io.ReadFull(stream, request[:]); err != nil || !bytes.Equal(request[:8], probeMagic[:]) {
		return
	}
	if ctx.Err() != nil || !authorized() {
		return
	}
	finished = WriteFull(stream, request[:]) == nil
}

func (c *Carrier) clearProbeSamples() {
	c.probe.mu.Lock()
	clear(c.probe.samples[:])
	c.probe.count, c.probe.next = 0, 0
	c.probe.mu.Unlock()
}

// Quality returns a detached snapshot. Missing/old capability and empty or
// retired windows return nil; no handshake duration is substituted for RTT.
func (c *Carrier) Quality() *model.CarrierQualityRuntime {
	if !c.ProbeSupported() {
		return nil
	}
	select {
	case <-c.Done():
		return nil
	default:
	}
	c.probe.mu.Lock()
	at := time.Now().UTC()
	out := &model.CarrierQualityRuntime{Source: "carrier_probe_v1", ObservedAt: at,
		IntervalMS: int(ProbeInterval / time.Millisecond), TimeoutMS: int(ProbeTimeout / time.Millisecond), WindowLimit: ProbeWindowLimit}
	var total time.Duration
	for i := 0; i < c.probe.count; i++ {
		s := c.probe.samples[(c.probe.next-c.probe.count+i+ProbeWindowLimit)%ProbeWindowLimit]
		if at.Sub(s.started) > probeWindowAge {
			continue
		}
		if out.WindowStartedAt.IsZero() {
			out.WindowStartedAt = s.started.UTC()
		}
		out.Samples++
		switch s.outcome {
		case 1:
			out.Timeouts++
		case 2:
			out.Errors++
		default:
			out.Successes++
			ms := float64(s.rtt) / float64(time.Millisecond)
			out.LatestRTTMS = ms
			out.LastSuccessAt = s.finished.UTC()
			if out.Successes == 1 || ms < out.MinRTTMS {
				out.MinRTTMS = ms
			}
			out.MaxRTTMS = max(out.MaxRTTMS, ms)
			total += s.rtt
		}
	}
	c.probe.mu.Unlock()
	if out.Samples == 0 {
		return nil
	}
	if out.Successes > 0 {
		out.MeanRTTMS = float64(total) / float64(time.Millisecond) / float64(out.Successes)
		if c.q != nil && !c.EstablishedAt.IsZero() {
			stats := c.q.ConnectionStats()
			if measuredQUICStats(stats) {
				out.QUIC = &model.QUICQualityRuntime{Source: "quic_go_rfc9002", StartedAt: c.EstablishedAt.Add(-c.HandshakeDuration).UTC(), ObservedAt: at,
					LatestRTTMS: float64(stats.LatestRTT) / float64(time.Millisecond), SmoothedRTTMS: float64(stats.SmoothedRTT) / float64(time.Millisecond), MinRTTMS: float64(stats.MinRTT) / float64(time.Millisecond),
					PacketsSent: stats.PacketsSent, PacketsReceived: stats.PacketsReceived, BytesSent: stats.BytesSent, BytesReceived: stats.BytesReceived, PacketsLost: stats.PacketsLost, BytesLost: stats.BytesLost}
			}
		}
	}
	return out
}

func measuredQUICStats(stats quic.ConnectionStats) bool {
	// quic-go 0.59 initializes RTT to 100 ms, including on path migration.
	// A successful control echo alone does not prove the local ACK estimator
	// has sampled the new path. A positive deviation is assigned on its first
	// valid RTT sample; omit native metrics when that evidence is unavailable.
	return stats.LatestRTT > 0 && stats.MeanDeviation > 0 && stats.PacketsReceived > 0
}
