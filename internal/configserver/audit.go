package configserver

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one human-readable admin action: who did what to which object.
type AuditEntry struct {
	Time   string `json:"time"`   // RFC3339
	Actor  string `json:"actor"`  // the admin
	Action string `json:"action"` // e.g. "save profile"
	Object string `json:"object"` // e.g. profile "team-a"
	IP     string `json:"ip"`
}

// Audit is an append-only JSONL log of admin actions (SEC-3).
type Audit struct {
	mu   sync.Mutex
	path string
}

// NewAudit opens (creates) the audit log under dir.
func NewAudit(dir string) *Audit { return &Audit{path: filepath.Join(dir, "audit.log")} }

// Log appends one entry. Failures are swallowed (auditing must not break actions,
// but the write is best-effort durable via O_APPEND).
func (a *Audit) Log(actor, action, object, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := AuditEntry{Time: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Object: object, IP: ip}
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// Tail returns up to the last n entries, newest first.
func (a *Audit) Tail(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	// newest first
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}
