// Package ipscanner is the IPScanner edge guard for Caddy (http.handlers.ipscanner).
package ipscanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	edge "github.com/ipscanner/ipscanner-edge-go"
	"go.uber.org/zap"
)

// Version is sent in the User-Agent as ipscanner-caddy/<Version>.
const Version = "0.1.3"

// Source is the X-IPScanner-Source value of this module.
const Source = "caddy"

// DefaultAPIKey is used when api_key is empty.
const DefaultAPIKey = "{env.IPSCANNER_API_KEY}"

// Request vars set on every check, readable as {http.vars.ipscanner.status} etc.
const (
	VarStatus = "ipscanner.status"
	VarClass  = "ipscanner.class"
	VarAction = "ipscanner.action"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler checks visitors with IPScanner before the next handler runs.
type Handler struct {
	// APIKey accepts placeholders. Default {env.IPSCANNER_API_KEY}; without a key every request passes unchecked.
	APIKey string `json:"api_key,omitempty"`
	// APIURL is the API base URL. Default https://ipscanner.io.
	APIURL string `json:"api_url,omitempty"`
	// SiteID is the dashboard site (site_...); mode and per class policy then come from the dashboard.
	SiteID string `json:"site_id,omitempty"`
	// Mode is monitor (default) or enforce; with a site only monitor has an effect.
	Mode string `json:"mode,omitempty"`
	// BlockClasses are blocked in enforce mode without a site. Default malicious_automation; "none" blocks nothing.
	BlockClasses []string `json:"block_classes,omitempty"`
	// Timeout is the budget for one check. Default 1.5s.
	Timeout caddy.Duration `json:"timeout,omitempty"`
	// CacheTTL is how long a verdict is reused per site, IP and user agent. Default 10m.
	CacheTTL caddy.Duration `json:"cache_ttl,omitempty"`
	// CacheSize bounds the verdict cache. Default 10000.
	CacheSize int `json:"cache_size,omitempty"`
	// PolicyTTL is how long the site policy is reused. Default 30s.
	PolicyTTL caddy.Duration `json:"policy_ttl,omitempty"`
	// SkipPaths is a case insensitive path regexp. Default: static assets; "none" checks every path.
	SkipPaths string `json:"skip_paths,omitempty"`
	// BlockMessage is the text of the 403 page.
	BlockMessage string `json:"block_message,omitempty"`
	// Debug adds X-IPScanner-Status, -Class and -Action to responses and logs every decision.
	Debug bool `json:"debug,omitempty"`

	guard  *edge.Guard
	logger *zap.Logger
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipscanner",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision creates the guard, so verdict and policy caches start empty after a config reload.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	g, err := edge.New(h.config(caddy.NewReplacer()))
	if err != nil {
		return configError(err)
	}
	h.guard = g
	return nil
}

func (h *Handler) config(repl *caddy.Replacer) edge.Config {
	replace := func(s string) string { return strings.TrimSpace(repl.ReplaceKnown(s, "")) }
	key := h.APIKey
	if strings.TrimSpace(key) == "" {
		key = DefaultAPIKey
	}
	var classes []string
	for _, c := range h.BlockClasses {
		classes = append(classes, replace(c))
	}
	return edge.Config{
		APIKey:       replace(key),
		APIURL:       replace(h.APIURL),
		SiteID:       replace(h.SiteID),
		Mode:         replace(h.Mode),
		BlockClasses: classes,
		Timeout:      time.Duration(h.Timeout),
		CacheTTL:     time.Duration(h.CacheTTL),
		CacheSize:    h.CacheSize,
		PolicyTTL:    time.Duration(h.PolicyTTL),
		// A regular expression may contain braces: no placeholders here.
		SkipPaths:    h.SkipPaths,
		Source:       Source,
		Client:       "caddy",
		Version:      Version,
		BlockMessage: replace(h.BlockMessage),
		Debug:        h.Debug,
		Logger:       h.logLine,
	}
}

func configError(err error) error {
	return errors.New(strings.NewReplacer(
		"apiUrl", "api_url",
		"siteId", "site_id",
		"blockClasses", "block_classes",
		"skipPaths", "skip_paths",
	).Replace(err.Error()))
}

func (h *Handler) Validate() error {
	if h.guard == nil {
		return errors.New("ipscanner: not provisioned")
	}
	for name, d := range map[string]caddy.Duration{"timeout": h.Timeout, "cache_ttl": h.CacheTTL, "policy_ttl": h.PolicyTTL} {
		if d < 0 {
			return fmt.Errorf("ipscanner: %s must not be negative", name)
		}
	}
	if h.CacheSize < 0 {
		return errors.New("ipscanner: cache_size must not be negative")
	}
	return nil
}

// ServeHTTP fails open: on a timeout or API error the request passes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	edge.StripHeaders(r.Header)

	v := edge.VisitorFrom(r, clientIP(r))
	// Use the path as the visitor sent it, before rewrites and handle_path.
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok && orig.URL != nil {
		v.Path = orig.URL.Path
	}
	if v.RequestID == "" {
		if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			if id, ok := repl.GetString("http.request.uuid"); ok {
				v.RequestID = id
			}
		}
	}

	d := h.guard.CheckVisitor(r.Context(), v)
	for name, value := range d.Headers() {
		r.Header.Set(name, value)
	}
	if h.guard.Debug() {
		for name, value := range d.DebugHeaders() {
			w.Header().Set(name, value)
		}
	}
	caddyhttp.SetVar(r.Context(), VarStatus, d.Status)
	if d.Status == edge.StatusOK {
		caddyhttp.SetVar(r.Context(), VarClass, d.Class)
		caddyhttp.SetVar(r.Context(), VarAction, d.Outcome)
	}

	if d.Blocked() {
		h.guard.WriteBlocked(w, d)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// clientIP is the IP Caddy resolved, so the server's trusted_proxies decide header trust.
func clientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func (h *Handler) logLine(line string) {
	logger := h.logger
	if logger == nil {
		logger = caddy.Log()
	}
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		logger.Info(line)
		return
	}
	message, warn := "check", false
	if s, ok := fields["status"].(string); ok && s != edge.StatusOK {
		message, warn = "check failed, request passed", true
	}
	if s, ok := fields["ipscanner"].(string); ok {
		message, warn = s, true
		delete(fields, "ipscanner")
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	zf := make([]zap.Field, 0, len(keys))
	for _, k := range keys {
		zf = append(zf, zap.Any(k, fields[k]))
	}
	if warn {
		logger.Warn(message, zf...)
		return
	}
	logger.Info(message, zf...)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
