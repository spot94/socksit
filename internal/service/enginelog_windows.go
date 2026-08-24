//go:build windows

package service

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TUNClientIP is the address applications appear as inside the tunnel: the TUN
// interface address from the generated engine config. Engine connection errors
// name it, e.g.
//
//	connection: connection upload closed: raw-read tcp4 172.19.0.1:65382->172.19.0.2:10419: ...
//
// which says nothing about WHICH application dropped the connection.
const TUNClientIP = "172.19.0.1"

// engineConnRe captures the client-side port of such a line.
var engineConnRe = regexp.MustCompile(`\b` + regexp.QuoteMeta(TUNClientIP) + `:(\d+)`)

// engineLogAnnotator tees the engine's output, naming the application behind
// those connection errors. The engine reports only tunnel-internal addresses, so
// on its own the log cannot distinguish "an app dropped its connection" from
// "the tunnel restarted". The owning process is looked up by source port through
// the Clash API, which carries processPath per connection.
type engineLogAnnotator struct {
	out       io.Writer
	clashAddr string

	mu      sync.Mutex
	partial []byte            // carry an unterminated line across writes
	ports   map[string]string // source port -> app name
	fetched time.Time
}

func newEngineLogAnnotator(out io.Writer, clashAddr string) *engineLogAnnotator {
	return &engineLogAnnotator{out: out, clashAddr: clashAddr, ports: map[string]string{}}
}

// Write splits the stream into lines and annotates the ones that name a tunnel
// client port. Unrecognised output passes through untouched.
func (a *engineLogAnnotator) Write(p []byte) (int, error) {
	a.mu.Lock()
	buf := append(a.partial, p...)
	var done []byte
	for {
		i := strings.IndexByte(string(buf), '\n')
		if i < 0 {
			break
		}
		line := buf[:i+1]
		buf = buf[i+1:]
		done = append(done, a.annotate(string(line))...)
	}
	a.partial = buf
	a.mu.Unlock()
	if len(done) > 0 {
		if _, err := a.out.Write(done); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// annotate appends " [app: name]" when the line names a client port we can map.
// Called with the lock held.
func (a *engineLogAnnotator) annotate(line string) string {
	m := engineConnRe.FindStringSubmatch(line)
	if m == nil {
		return line
	}
	port := m[1]
	name, ok := a.ports[port]
	if !ok && time.Since(a.fetched) > time.Second {
		a.refreshLocked()
		name, ok = a.ports[port]
	}
	if !ok || name == "" {
		return line
	}
	return strings.TrimRight(line, "\r\n") + " [app: " + name + "]\n"
}

// refreshLocked reloads the port -> app map from the engine's Clash API. Errors
// are ignored: annotation is a nicety, never a reason to lose a log line.
func (a *engineLogAnnotator) refreshLocked() {
	a.fetched = time.Now()
	if strings.TrimSpace(a.clashAddr) == "" {
		return
	}
	client := &http.Client{Timeout: 400 * time.Millisecond}
	resp, err := client.Get("http://" + a.clashAddr + "/connections")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var payload struct {
		Connections []struct {
			Metadata struct {
				SourcePort  string `json:"sourcePort"`
				ProcessPath string `json:"processPath"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload) != nil {
		return
	}
	fresh := make(map[string]string, len(payload.Connections))
	for _, c := range payload.Connections {
		if p := c.Metadata.SourcePort; p != "" && c.Metadata.ProcessPath != "" {
			fresh[p] = baseName(c.Metadata.ProcessPath)
		}
	}
	// Keep previously seen ports: a closing connection may already be gone from
	// the API by the time its error is logged.
	for k, v := range fresh {
		a.ports[k] = v
	}
	if len(a.ports) > 4096 {
		a.ports = fresh
	}
}

// baseName is filepath.Base for Windows paths reported by the engine, which are
// always absolute with backslashes.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
