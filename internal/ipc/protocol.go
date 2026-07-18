// Package ipc is the local control channel between the user-session UI (tray +
// GUI) and the LocalSystem service. Transport is a go-winio named pipe secured
// by an SDDL DACL (deny-by-default, kernel-enforced). See plan U8/KTD5.
package ipc

// DefaultPipeName is the production pipe path. The ProtectedPrefix\Administrators
// namespace requires the creator to be an admin/SYSTEM, preventing a low-priv
// process from squatting the name.
const DefaultPipeName = `\\.\pipe\ProtectedPrefix\Administrators\SocksIt\svc`

// Operations.
const (
	OpStatus       = "status"
	OpGetConfig    = "get_config"
	OpSetConfig    = "set_config"
	OpSetCreds     = "set_credentials"
	OpToggle       = "toggle"
	OpReload       = "reload"
	OpStats        = "stats"
	OpUpdateStatus = "update_status"
	OpUpdateCheck  = "update_check"
)

// Request is a single control call. Args carries operation parameters; it is
// never written to the audit log (so credentials in Args do not leak).
type Request struct {
	Op   string            `json:"op"`
	Args map[string]string `json:"args,omitempty"`
}

// Response is the reply. Data holds the JSON payload for read operations.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  []byte `json:"data,omitempty"`
}

// Handler implements the service-side operations. Implementations must never
// return secret values in Status/Stats payloads.
type Handler interface {
	Status() (any, error)
	GetConfig() (string, error)
	SetConfig(yamlText string) error
	SetCredentials(user, pass string) error
	Toggle(on bool) error
	Reload() error
	Stats() (any, error)
	UpdateStatus() (any, error)
	UpdateCheck() (any, error)
}
