package ipscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

const (
	ipResidential = "84.128.0.1"
	ipTor         = "185.220.101.1"
	ipVPN         = "185.217.69.166"
	ipHosting     = "5.9.0.1"
	chromeUA      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

type fakeAPI struct {
	srv *httptest.Server

	mu      sync.Mutex
	checks  []map[string]interface{}
	headers []http.Header
	policy  string // JSON body, "" = 404
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

var classes = map[string][2]string{ // ip -> traffic class, network class
	ipResidential: {"human", "residential_clean"},
	ipTor:         {"tor", "tor"},
	ipVPN:         {"vpn", "vpn"},
	ipHosting:     {"hosting", "hosting"},
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/edge/check":
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		f.checks = append(f.checks, body)
		c, ok := classes[fmt.Sprint(body["ip"])]
		if !ok {
			c = [2]string{"human", "residential_clean"}
		}
		site := "null"
		if s, _ := body["site"].(string); s != "" {
			site = fmt.Sprintf(`{"id":%q,"mode":"enforce","policyVersion":1}`, s)
		}
		fmt.Fprintf(w, `{"class":%q,"agent":{"class":"human","confidence":0.9,"action":"allow","signals":{}},"network":{"networkClass":%q,"anonymized":%t,"riskScore":10,"country":"DE"},"site":%s}`,
			c[0], c[1], c[0] != "human", site)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sites/"):
		if f.policy == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		fmt.Fprint(w, f.policy)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeAPI) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.checks)
}

func (f *fakeAPI) lastHeaders() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.headers) == 0 {
		return nil
	}
	return f.headers[len(f.headers)-1]
}

func (f *fakeAPI) lastCheck() map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.checks) == 0 {
		return nil
	}
	return f.checks[len(f.checks)-1]
}

func provision(t *testing.T, h *Handler) *Handler {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return h
}

// request mimics Caddy's server: resolved client IP var, replacer and original request.
func request(clientIP, path, ua string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	r.RemoteAddr = "172.18.0.1:40000"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html")
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: clientIP})
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.OriginalRequestCtxKey, *r.Clone(context.Background()))
	return r.WithContext(ctx)
}

type nextHandler struct {
	called bool
	header http.Header
}

func (n *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	n.called = true
	n.header = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
	return nil
}

func serve(t *testing.T, h *Handler, r *http.Request) (*httptest.ResponseRecorder, *nextHandler) {
	t.Helper()
	w := httptest.NewRecorder()
	next := &nextHandler{}
	if err := h.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP returned %v", err)
	}
	return w, next
}

func TestCaddyModule(t *testing.T) {
	info := Handler{}.CaddyModule()
	if info.ID != "http.handlers.ipscanner" {
		t.Fatalf("id %q", info.ID)
	}
	if _, ok := info.New().(*Handler); !ok {
		t.Fatal("New does not return *Handler")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ipscanner {
		api_key {env.IPSCANNER_API_KEY}
		api_url http://localhost:3050
		site_id site_abc123
		mode enforce
		block_classes malicious_automation tor
		block_classes vpn
		timeout 800ms
		cache_ttl 5m
		cache_size 500
		policy_ttl 1m
		skip_paths "^/health$"
		block_message "Not here."
		debug
	}`)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	want := Handler{
		APIKey:       "{env.IPSCANNER_API_KEY}",
		APIURL:       "http://localhost:3050",
		SiteID:       "site_abc123",
		Mode:         "enforce",
		BlockClasses: []string{"malicious_automation", "tor", "vpn"},
		Timeout:      caddy.Duration(800 * time.Millisecond),
		CacheTTL:     caddy.Duration(5 * time.Minute),
		CacheSize:    500,
		PolicyTTL:    caddy.Duration(time.Minute),
		SkipPaths:    "^/health$",
		BlockMessage: "Not here.",
		Debug:        true,
	}
	got, _ := json.Marshal(h)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("got  %s\nwant %s", got, exp)
	}
}

func TestUnmarshalCaddyfileBare(t *testing.T) {
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`ipscanner`)); err != nil {
		t.Fatal(err)
	}
	if h.APIKey != "" || h.Debug {
		t.Fatalf("%+v", h)
	}
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("ipscanner {\n debug false\n}")); err != nil || h.Debug {
		t.Fatalf("debug false: %v %+v", err, h)
	}
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	for _, input := range []string{
		`ipscanner pk_live_inline`,
		"ipscanner {\n unknown 1\n}",
		"ipscanner {\n api_key\n}",
		"ipscanner {\n api_key a b\n}",
		"ipscanner {\n mode\n}",
		"ipscanner {\n block_classes\n}",
		"ipscanner {\n timeout soon\n}",
		"ipscanner {\n cache_ttl 1m 2m\n}",
		"ipscanner {\n cache_size many\n}",
		"ipscanner {\n debug maybe\n}",
		"ipscanner {\n debug true false\n}",
	} {
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Errorf("no error for %q", input)
		}
	}
}

// The directive is ordered by the module itself: no global "order" line.
func TestDirectiveOrder(t *testing.T) {
	input := `:8080 {
	reverse_proxy localhost:9000
	ipscanner {
		mode enforce
	}
	basic_auth /admin/* {
		admin $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
	header X-Frame-Options DENY
}`
	adapter := caddyconfig.GetAdapter("caddyfile")
	out, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapt: %v (warnings %v)", err, warnings)
	}
	s := string(out)
	pos := func(handler string) int {
		i := strings.Index(s, `"handler":"`+handler+`"`)
		if i < 0 {
			t.Fatalf("%s missing in %s", handler, s)
		}
		return i
	}
	if !(pos("headers") < pos("ipscanner") && pos("ipscanner") < pos("authentication") && pos("authentication") < pos("reverse_proxy")) {
		t.Fatalf("order: %s", s)
	}
	if !strings.Contains(s, `"mode":"enforce"`) {
		t.Fatalf("config: %s", s)
	}
}

func TestJSONConfig(t *testing.T) {
	var h Handler
	raw := `{"api_key":"k","site_id":"site_abc","mode":"monitor","block_classes":["tor"],"timeout":"1s","cache_ttl":"10m","policy_ttl":30000000000,"cache_size":20,"skip_paths":"none","debug":true}`
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		t.Fatal(err)
	}
	if h.Timeout != caddy.Duration(time.Second) || h.CacheTTL != caddy.Duration(10*time.Minute) || h.PolicyTTL != caddy.Duration(30*time.Second) || h.CacheSize != 20 || !h.Debug || h.BlockClasses[0] != "tor" {
		t.Fatalf("%+v", h)
	}
}

func TestPlaceholders(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("pk_test_from_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPSCANNER_API_KEY", "pk_test_from_env")
	t.Setenv("IPSCANNER_TEST_SITE", "site_fromenv")

	h := &Handler{}
	cfg := h.config(caddy.NewReplacer())
	if cfg.APIKey != "pk_test_from_env" {
		t.Fatal("default api_key does not read IPSCANNER_API_KEY")
	}
	if cfg.Source != "caddy" || cfg.Client != "caddy" || cfg.Version != Version {
		t.Fatalf("source %q client %q version %q", cfg.Source, cfg.Client, cfg.Version)
	}

	h = &Handler{APIKey: "{file." + keyFile + "}", SiteID: "{env.IPSCANNER_TEST_SITE}", SkipPaths: `^/a{2}$`}
	cfg = h.config(caddy.NewReplacer())
	if cfg.APIKey != "pk_test_from_file" || cfg.SiteID != "site_fromenv" || cfg.SkipPaths != `^/a{2}$` {
		t.Fatalf("file key %v, site %q, skip %q", cfg.APIKey == "pk_test_from_file", cfg.SiteID, cfg.SkipPaths)
	}
}

func TestProvisionErrors(t *testing.T) {
	for _, h := range []*Handler{
		{SiteID: "nope"},
		{Mode: "block"},
		{BlockClasses: []string{"human"}},
		{SkipPaths: "("},
		{APIURL: "ftp://x"},
	} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		err := h.Provision(ctx)
		cancel()
		if err == nil {
			t.Errorf("no error for %+v", h)
			continue
		}
		if strings.Contains(err.Error(), "siteId") || strings.Contains(err.Error(), "skipPaths") || strings.Contains(err.Error(), "apiUrl") {
			t.Errorf("error names a core field: %v", err)
		}
	}
	h := provision(t, &Handler{APIKey: "k"})
	h.CacheSize = -1
	if h.Validate() == nil {
		t.Error("negative cache_size accepted")
	}
	h.CacheSize, h.Timeout = 0, -1
	if h.Validate() == nil {
		t.Error("negative timeout accepted")
	}
}

func TestEnforceNoSite(t *testing.T) {
	api := newFakeAPI(t)
	h := provision(t, &Handler{APIKey: "pk_test_x", APIURL: api.srv.URL, Mode: "enforce", BlockClasses: []string{"tor"}, Debug: true})

	r := request(ipResidential, "/page", chromeUA)
	r.Header.Set("X-IPScanner-Class", "verified_bot") // spoofed verdict
	w, next := serve(t, h, r)
	if !next.called || w.Code != 200 {
		t.Fatalf("residential: next %v code %d", next.called, w.Code)
	}
	if next.header.Get("X-IPScanner-Status") != "ok" || next.header.Get("X-IPScanner-Class") != "human" || next.header.Get("X-IPScanner-Action") != "allow" {
		t.Fatalf("upstream headers %v", next.header)
	}
	if next.header.Get("X-IPScanner-Site") != "" || next.header.Get("X-IPScanner-Network-Class") != "residential_clean" {
		t.Fatalf("upstream headers %v", next.header)
	}
	if w.Header().Get("X-IPScanner-Class") != "human" {
		t.Fatalf("debug headers %v", w.Header())
	}
	if caddyhttp.GetVar(r.Context(), VarStatus) != "ok" || caddyhttp.GetVar(r.Context(), VarClass) != "human" || caddyhttp.GetVar(r.Context(), VarAction) != "allow" {
		t.Fatal("vars not set")
	}

	hd := api.lastHeaders()
	if hd.Get("X-IPScanner-Source") != "caddy" || hd.Get("User-Agent") != "ipscanner-caddy/"+Version || hd.Get("Authorization") != "Bearer pk_test_x" {
		t.Fatalf("api headers %v", hd)
	}
	body := api.lastCheck()
	if body["ip"] != ipResidential || body["user_agent"] != chromeUA {
		t.Fatalf("check body %v", body)
	}
	if id, _ := body["request_id"].(string); len(id) != 36 {
		t.Fatalf("request_id %q", id)
	}

	r = request(ipTor, "/page", chromeUA)
	w, next = serve(t, h, r)
	if next.called || w.Code != 403 || !strings.Contains(w.Body.String(), "Blocked by IPScanner") {
		t.Fatalf("tor: next %v code %d", next.called, w.Code)
	}
	if w.Header().Get("X-IPScanner-Action") != "block" || caddyhttp.GetVar(r.Context(), VarAction) != "block" {
		t.Fatalf("tor headers %v", w.Header())
	}

	_, next = serve(t, h, request(ipVPN, "/page", chromeUA))
	if !next.called || next.header.Get("X-IPScanner-Class") != "vpn" || next.header.Get("X-IPScanner-Action") != "allow" {
		t.Fatalf("vpn: %v", next.header)
	}
}

func TestMonitorDefault(t *testing.T) {
	api := newFakeAPI(t)
	h := provision(t, &Handler{APIKey: "k", APIURL: api.srv.URL, BlockClasses: []string{"tor"}})
	w, next := serve(t, h, request(ipTor, "/", chromeUA))
	if !next.called || w.Code != 200 || next.header.Get("X-IPScanner-Action") != "would_block" {
		t.Fatalf("monitor: %d %v", w.Code, next.header)
	}
	if w.Header().Get("X-IPScanner-Status") != "" {
		t.Fatal("debug headers without debug")
	}
}

func TestSitePolicy(t *testing.T) {
	api := newFakeAPI(t)
	api.policy = `{"mode":"enforce","policy":{"tor":"block","vpn":"flag","verified_bot":"block"},"version":1}`
	h := provision(t, &Handler{APIKey: "k", APIURL: api.srv.URL, SiteID: "site_abc123"})

	w, next := serve(t, h, request(ipTor, "/", chromeUA))
	if next.called || w.Code != 403 {
		t.Fatalf("tor: %d", w.Code)
	}
	_, next = serve(t, h, request(ipVPN, "/", chromeUA))
	if !next.called || next.header.Get("X-IPScanner-Action") != "flag" || next.header.Get("X-IPScanner-Site") != "site_abc123" {
		t.Fatalf("vpn: %v", next.header)
	}
	if api.lastCheck()["site"] != "site_abc123" {
		t.Fatal("site not sent")
	}

	// mode monitor in the Caddyfile wins over an enforce policy.
	h = provision(t, &Handler{APIKey: "k", APIURL: api.srv.URL, SiteID: "site_abc123", Mode: "monitor"})
	w, next = serve(t, h, request(ipTor, "/", chromeUA))
	if !next.called || w.Code != 200 || next.header.Get("X-IPScanner-Action") != "would_block" {
		t.Fatalf("monitor override: %d %v", w.Code, next.header)
	}
}

func TestCacheAndSkip(t *testing.T) {
	api := newFakeAPI(t)
	h := provision(t, &Handler{APIKey: "k", APIURL: api.srv.URL})
	serve(t, h, request(ipResidential, "/", chromeUA))
	serve(t, h, request(ipResidential, "/other", chromeUA))
	if n := api.checkCount(); n != 1 {
		t.Fatalf("want 1 check (cache hit), got %d", n)
	}
	serve(t, h, request(ipResidential, "/", chromeUA+" other"))
	if n := api.checkCount(); n != 2 {
		t.Fatalf("another user agent is another visitor: %d", n)
	}

	r := request(ipTor, "/app.css", chromeUA)
	_, next := serve(t, h, r)
	if api.checkCount() != 2 || next.header.Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("skip: %d %v", api.checkCount(), next.header)
	}
	r = request(ipTor, "/style.css", chromeUA)
	r.URL.Path = "/index.php" // rewritten by try_files
	serve(t, h, r)
	if api.checkCount() != 2 {
		t.Fatal("skip_paths did not use the original path")
	}
	if caddyhttp.GetVar(r.Context(), VarClass) != nil {
		t.Fatal("class var set on a skipped request")
	}
}

func TestClientIP(t *testing.T) {
	api := newFakeAPI(t)
	h := provision(t, &Handler{APIKey: "k", APIURL: api.srv.URL, Mode: "enforce", BlockClasses: []string{"tor"}})

	// Caddy resolved a private peer: X-Forwarded-For is not read here.
	r := request("172.18.0.1", "/", chromeUA)
	r.Header.Set("X-Forwarded-For", ipTor)
	w, next := serve(t, h, r)
	if !next.called || w.Code != 200 || next.header.Get("X-IPScanner-Status") != "skipped" || api.checkCount() != 0 {
		t.Fatalf("spoofed XFF: %d %v", w.Code, next.header)
	}

	// No client_ip var: the peer address.
	r = httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = ipTor + ":5000"
	r.Header.Set("User-Agent", chromeUA)
	w, _ = serve(t, h, r)
	if w.Code != 403 {
		t.Fatalf("peer address: %d", w.Code)
	}
}

func TestFailOpen(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	h := provision(t, &Handler{APIKey: "k", APIURL: url, Mode: "enforce", BlockClasses: []string{"tor"}, Timeout: caddy.Duration(300 * time.Millisecond)})

	start := time.Now()
	w, next := serve(t, h, request(ipTor, "/", chromeUA))
	if !next.called || w.Code != 200 || next.header.Get("X-IPScanner-Status") != "error" {
		t.Fatalf("dead api: %d %v", w.Code, next.header)
	}
	_, next = serve(t, h, request(ipTor, "/", chromeUA+" 2"))
	if next.header.Get("X-IPScanner-Status") != "backoff" {
		t.Fatalf("no backoff: %v", next.header)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("fail open took %s", time.Since(start))
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	h = provision(t, &Handler{APIKey: "k", APIURL: slow.URL, Mode: "enforce", BlockClasses: []string{"tor"}, Timeout: caddy.Duration(200 * time.Millisecond)})
	start = time.Now()
	_, next = serve(t, h, request(ipTor, "/", chromeUA))
	if !next.called || next.header.Get("X-IPScanner-Status") != "timeout" || time.Since(start) > time.Second {
		t.Fatalf("slow api: %v after %s", next.header, time.Since(start))
	}
}

func TestNoKey(t *testing.T) {
	t.Setenv("IPSCANNER_API_KEY", "")
	h := provision(t, &Handler{Mode: "enforce", BlockClasses: []string{"tor"}})
	w, next := serve(t, h, request(ipTor, "/", chromeUA))
	if !next.called || w.Code != 200 || next.header.Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("no key: %d %v", w.Code, next.header)
	}
}

func TestLogLine(t *testing.T) {
	h := &Handler{}
	h.logLine(`{"ipscanner":"upstream failure","status":"error","code":0}`)
	h.logLine(`{"ip":"1.2.3.4","status":"timeout","decision":"allow"}`)
	h.logLine(`{"ip":"1.2.3.4","trafficClass":"human","decision":"allow"}`)
	h.logLine(`not json`)
}
