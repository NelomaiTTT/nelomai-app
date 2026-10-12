package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

const maxFrame = 64 * 1024

type identity struct {
	GUID  string `json:"guid"`
	LUID  uint64 `json:"luid"`
	Index uint32 `json:"index"`
}
type request struct {
	ID            uint64   `json:"id"`
	Session       uint64   `json:"session"`
	Op            string   `json:"op"`
	DeadlineMS    uint32   `json:"deadline_ms,omitempty"`
	Name          string   `json:"name,omitempty"`
	GUID          string   `json:"guid,omitempty"`
	DLLSHA256     string   `json:"dll_sha256,omitempty"`
	Slot          uint32   `json:"slot,omitempty"`
	Configuration string   `json:"configuration,omitempty"`
	Physical      identity `json:"physical,omitempty"`
	Source        string   `json:"source,omitempty"`
	Target        string   `json:"target,omitempty"`
	DNS           []byte   `json:"dns,omitempty"`
	Probe         uint64   `json:"probe,omitempty"`
	AwaitAbsence  *bool    `json:"await_absence,omitempty"`
}
type response struct {
	Closed     bool                    `json:"closed"`
	ID         uint64                  `json:"id"`
	Session    uint64                  `json:"session"`
	OK         bool                    `json:"ok"`
	Error      string                  `json:"error,omitempty"`
	Identity   identity                `json:"identity"`
	Handshakes [2]int64                `json:"handshakes"`
	Counters   RedundantTunnelCounters `json:"counters"`
	Probe      uint64                  `json:"probe,omitempty"`
	DNS        []byte                  `json:"dns,omitempty"`
	Absent     bool                    `json:"absent"`
	ElapsedMS  int64                   `json:"elapsed_ms"`
}
type workerProbe struct {
	token      ProbeToken
	slot       uint32
	generation uint64
	expires    time.Time
}
type worker struct {
	owner       nativeOwner
	session     uint64
	started     bool
	identity    identity
	tunnel      *RedundantTunnel
	slots       [2]*device.Device
	generations [2]uint64
	probes      map[uint64]workerProbe
	nextProbe   uint64
	closeDone   bool
}

func newWorker() *worker {
	return &worker{owner: newNativeOwner(), probes: make(map[uint64]workerProbe)}
}
func runWorker(input io.Reader, output io.Writer) error { return newWorker().serve(input, output) }

func (w *worker) serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxFrame+1)
	encoder := json.NewEncoder(output)
	var lastID uint64
	for scanner.Scan() {
		var req request
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		parseErr := decoder.Decode(&req)
		var extra any
		if parseErr != nil || len(scanner.Bytes()) > maxFrame || decoder.Decode(&extra) != io.EOF || req.ID <= lastID || req.Session == 0 {
			_, _ = w.bounded(request{Op: "stop", ID: req.ID, Session: w.session})
			return errors.New("invalid_worker_frame")
		}
		lastID = req.ID
		reply, terminal := w.bounded(req)
		if err := encoder.Encode(reply); err != nil {
			_, _ = w.bounded(request{Op: "stop"})
			return errors.New("worker_output_closed")
		}
		if terminal {
			return nil
		}
	}
	// Losing the inherited input pipe is a terminal lifecycle event.
	reply, terminal := w.bounded(request{Op: "stop", Session: w.session})
	if !terminal || !reply.OK || !reply.Absent {
		return errors.New("worker_eof_stop_failed")
	}
	return scanner.Err()
}
func (w *worker) bounded(req request) (response, bool) {
	limit := time.Second
	switch req.Op {
	case "start":
		limit = 30 * time.Second
	case "attach":
		limit = 10 * time.Second
	case "stop":
		limit = 8 * time.Second
	}
	if req.DeadlineMS > 0 && time.Duration(req.DeadlineMS)*time.Millisecond < limit {
		limit = time.Duration(req.DeadlineMS) * time.Millisecond
	}
	operation := req.Op
	switch operation {
	case "start", "attach", "switch", "sample", "probe_send", "probe_poll", "probe_cancel", "stop":
	default:
		operation = "protocol"
	}
	started := time.Now()
	done := make(chan response, 1)
	go func() {
		reply := response{ID: req.ID, Session: req.Session}
		err := w.command(req, &reply)
		reply.OK = err == nil
		if err != nil {
			reply.Error = operation + "_failed"
		}
		reply.Identity = w.identity
		for index, slot := range w.slots {
			if slot != nil {
				reply.Handshakes[index] = slot.LatestHandshakeUnixMillis()
			}
		}
		if w.tunnel != nil {
			reply.Counters = w.tunnel.Counters()
			reply.Closed = w.tunnel.Closed()
		}
		if req.Op == "stop" {
			reply.Closed = w.closeDone
		}
		reply.ElapsedMS = time.Since(started).Milliseconds()
		done <- reply
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case reply := <-done:
		return reply, req.Op == "stop" && (w.session == 0 || req.Session == 0 || req.Session == w.session)
	case <-timer.C:
		// No subsequent command or cleanup races this native operation. The process
		// exits after the terminal timeout ACK; parent retains its original HANDLE.
		return response{ID: req.ID, Session: req.Session, Error: operation + "_timeout", ElapsedMS: time.Since(started).Milliseconds()}, true
	}
}
func (w *worker) command(req request, reply *response) error {
	if req.Op != "start" && req.Op != "stop" && (w.tunnel == nil || w.session != req.Session) {
		return errors.New("invalid_session")
	}
	switch req.Op {
	case "start":
		digest, err := hex.DecodeString(req.DLLSHA256)
		if w.started || req.Name == "" || len(req.Name) > 100 || req.GUID == "" || err != nil || len(digest) != 32 {
			return errors.New("invalid_start")
		}
		w.started = true
		w.session = req.Session
		real, ident, err := w.owner.start(req)
		w.identity = ident
		if err != nil {
			return err
		}
		dispatcher, err := NewRedundantTunnel(real)
		if err != nil {
			return err
		}
		w.tunnel = dispatcher
		w.session = req.Session
		return nil
	case "attach":
		if req.Slot >= 2 || w.slots[req.Slot] != nil || req.Configuration == "" || w.tunnel.Closed() {
			return errors.New("invalid_slot")
		}
		bind, err := w.owner.newBind(req.Physical)
		if err != nil {
			return err
		}
		attachment, err := w.tunnel.AttachSlot(req.Slot)
		if err != nil {
			return err
		}
		backend := device.NewDevice(attachment, bind, device.NewLogger(device.LogLevelSilent, ""))
		if err := backend.IpcSet(req.Configuration); err != nil {
			backend.Close()
			w.tunnel.ResetSlot(req.Slot)
			return err
		}
		if err := backend.Up(); err != nil {
			backend.Close()
			w.tunnel.ResetSlot(req.Slot)
			return err
		}
		w.generations[req.Slot]++
		w.slots[req.Slot] = backend
		backend.SendKeepalivesToAllRunningPeers()
		return nil
	case "switch":
		if req.Slot >= 2 || w.slots[req.Slot] == nil {
			return errors.New("missing_slot")
		}
		select {
		case <-w.slots[req.Slot].Wait():
			return errors.New("closed_slot")
		default:
		}
		return w.tunnel.SwitchActive(req.Slot)
	case "sample":
		return nil
	case "probe_send":
		return w.sendProbe(req, reply)
	case "probe_poll":
		probe, ok := w.probes[req.Probe]
		if !ok || probe.generation != w.generations[probe.slot] || !time.Now().Before(probe.expires) {
			w.cancelProbe(req.Probe)
			return errors.New("expired_probe")
		}
		reply.Probe = req.Probe
		reply.DNS = w.tunnel.TakeProbeReply(probe.token)
		return nil
	case "probe_cancel":
		if !w.cancelProbe(req.Probe) {
			return errors.New("missing_probe")
		}
		return nil
	case "stop":
		if w.session != 0 && req.Session != 0 && w.session != req.Session {
			return errors.New("wrong_stop_session")
		}
		await := req.AwaitAbsence == nil || *req.AwaitAbsence
		absent, err := w.stop(await)
		reply.Absent = absent
		return err
	default:
		return errors.New("unsupported_operation")
	}
}
func (w *worker) stop(await bool) (bool, error) {
	for id := range w.probes {
		w.cancelProbe(id)
	}
	var closeErr error
	if w.tunnel != nil {
		closeErr = w.tunnel.Close()
	}
	if w.tunnel == nil {
		closeErr = w.owner.closeTun()
	}
	for _, slot := range w.slots {
		if slot != nil {
			slot.Close()
			<-slot.Wait()
		}
	}
	if closeErr == nil {
		w.closeDone = true
	}
	// Parent-owned filters may pin the interface row. Native close ACK and
	// process exit precede parent filter retirement; absence stays explicit.
	if !await {
		return false, closeErr
	}
	deadline := time.Now().Add(7 * time.Second)
	for {
		absent, err := w.owner.absent(w.identity)
		if err != nil {
			return false, err
		}
		if absent {
			return true, closeErr
		}
		if time.Now().After(deadline) {
			return false, errors.New("owned_identity_still_present")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func (w *worker) cancelProbe(id uint64) bool {
	probe, ok := w.probes[id]
	if !ok {
		return false
	}
	delete(w.probes, id)
	w.tunnel.CancelProbe(probe.token)
	return true
}
func (w *worker) sendProbe(req request, reply *response) error {
	for id, probe := range w.probes {
		if !time.Now().Before(probe.expires) {
			w.cancelProbe(id)
		}
	}
	if req.Slot >= 2 || w.slots[req.Slot] == nil || len(w.probes) >= 64 || len(req.DNS) < 12 || len(req.DNS) > 4096 || req.DNS[2]&0x80 != 0 {
		return errors.New("invalid_probe")
	}
	source, err := netip.ParseAddr(req.Source)
	if err != nil || !source.Is4() || source.IsUnspecified() || source.IsMulticast() || source.IsLoopback() {
		return errors.New("invalid_source")
	}
	target, err := netip.ParseAddr(req.Target)
	if err != nil || !target.Is4() || target.IsUnspecified() || target.IsMulticast() || target.IsLoopback() {
		return errors.New("invalid_target")
	}
	for attempt := 0; attempt < 16; attempt++ {
		var random [2]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return err
		}
		token := ProbeToken{Port: 49152 + binary.BigEndian.Uint16(random[:])%16384, DNSID: binary.BigEndian.Uint16(req.DNS[:2])}
		packet := make([]byte, 28+len(req.DNS))
		packet[0] = 0x45
		packet[6] = 0x40
		packet[8] = 64
		packet[9] = 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		src, dst := source.As4(), target.As4()
		copy(packet[12:16], src[:])
		copy(packet[16:20], dst[:])
		binary.BigEndian.PutUint16(packet[20:22], token.Port)
		binary.BigEndian.PutUint16(packet[22:24], 53)
		binary.BigEndian.PutUint16(packet[24:26], uint16(len(req.DNS)+8))
		copy(packet[28:], req.DNS)
		var sum uint32
		for at := 0; at < 20; at += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[at : at+2]))
		}
		for sum > 0xffff {
			sum = (sum >> 16) + (sum & 0xffff)
		}
		binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
		err := w.tunnel.InjectProbe(req.Slot, packet, token)
		if errors.Is(err, ErrProbeAlreadyPending) {
			continue
		}
		if err != nil {
			return err
		}
		w.nextProbe++
		if w.nextProbe == 0 {
			w.tunnel.CancelProbe(token)
			return errors.New("probe_id_exhausted")
		}
		w.probes[w.nextProbe] = workerProbe{token: token, slot: req.Slot, generation: w.generations[req.Slot], expires: time.Now().Add(8 * time.Second)}
		reply.Probe = w.nextProbe
		return nil
	}
	return errors.New("probe_tuple_exhausted")
}

// Configuration is only passed to IpcSet; sanitize protocol failures above rather
// than returning parser messages that may contain keys or user configuration.
