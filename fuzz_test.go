package ipscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	edge "github.com/ipscanner/ipscanner-edge-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// FuzzUnmarshalCaddyfile checks that any parsed block survives the JSON round trip Caddy does after adapting.
func FuzzUnmarshalCaddyfile(f *testing.F) {
	f.Add("ipscanner {\n\tapi_key {env.IPSCANNER_API_KEY}\n\tsite_id site_abc123\n\tmode enforce\n\tblock_classes tor vpn\n\ttimeout 1500ms\n\tcache_ttl 10m\n\tcache_size 500\n\tpolicy_ttl 30s\n\tskip_paths \"^/health$\"\n\tblock_message \"Go away\"\n\tdebug\n}")
	f.Add("ipscanner {\n\tdebug false\n\tblock_classes none\n\tblock_classes proxy\n}")
	f.Add("ipscanner {\n\ttimeout -1s\n\tcache_size -5\n}")
	f.Add("ipscanner {\n\tskip_paths `\\.(css|js)$`\n\tapi_url http://127.0.0.1:3050\n}")
	f.Add("ipscanner")
	f.Add("ipscanner {\n\tcache_size 99999999999999999999\n}")
	f.Fuzz(func(t *testing.T, input string) {
		tokens, err := caddyfile.Tokenize([]byte(input), "Caddyfile")
		if err != nil {
			return
		}
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens)); err != nil {
			return
		}
		b1, err := json.Marshal(&h)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var h2 Handler
		if err := json.Unmarshal(b1, &h2); err != nil {
			t.Fatalf("unmarshal %s: %v", b1, err)
		}
		if b2, _ := json.Marshal(&h2); !bytes.Equal(b1, b2) {
			t.Fatalf("JSON round trip changed the config:\n%s\n%s", b1, b2)
		}
	})
}

type fuzzAPI struct {
	mu     sync.Mutex
	checks int
	lastIP string
}

func (a *fuzzAPI) serve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	a.mu.Lock()
	a.checks++
	a.lastIP = body.IP
	a.mu.Unlock()
	c, ok := classes[body.IP]
	if !ok {
		c = [2]string{"human", "residential_clean"}
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"class":%q,"network":{"networkClass":%q,"anonymized":false,"riskScore":10,"country":"DE"},"site":null}`, c[0], c[1])
}

func (a *fuzzAPI) last() (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checks, a.lastIP
}

// FuzzServeHTTP checks that the module uses only the client IP Caddy resolved, never a visitor header,
// and that forged X-IPScanner-* headers never reach the next handler.
func FuzzServeHTTP(f *testing.F) {
	api := &fuzzAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.serve))
	defer srv.Close()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{APIKey: "pk_test_fuzz", APIURL: srv.URL, Mode: "enforce", BlockClasses: []string{"tor", "vpn"}}
	if err := h.Provision(ctx); err != nil {
		f.Fatal(err)
	}
	// A keyless guard skips every visitor but reports the IP the core would check.
	norm, err := edge.New(edge.Config{Logger: func(string) {}})
	if err != nil {
		f.Fatal(err)
	}

	f.Add(ipResidential, "172.18.0.1:40000", ipTor, "X-IPScanner-Class", "verified_bot", "/", chromeUA)
	f.Add("", ipTor+":5000", ipResidential, "x-ipscanner-action", "allow", "/login", chromeUA)
	f.Add("172.18.0.1", "172.18.0.1:40000", ipTor, "X-Ipscanner-Status", "ok", "/", chromeUA)
	f.Add("::ffff:"+ipVPN, "[::1]:1", "", "X-IPSCANNER-SITE", "site_x", "/app.css", "")
	f.Add("not an ip", "nonsense", ipTor, "Cookie", "c=1", "/", "curl/8")
	f.Fuzz(func(t *testing.T, clientVar, remote, xff, forgedName, forgedValue, path, ua string) {
		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		r.URL.Path = path
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("X-IPScanner-Class", "verified_bot")
		r.Header[forgedName] = append(r.Header[forgedName], forgedValue)
		vars := map[string]any{}
		if clientVar != "" {
			vars[caddyhttp.ClientIPVarKey] = clientVar
		}
		rctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars)
		rctx = context.WithValue(rctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
		r = r.WithContext(rctx)

		resolved := clientVar
		if resolved == "" {
			resolved, _, _ = net.SplitHostPort(remote)
		}
		before, _ := api.last()

		w := httptest.NewRecorder()
		next := &nextHandler{}
		if err := h.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}

		if after, ip := api.last(); after != before {
			if want := norm.CheckVisitor(context.Background(), edge.Visitor{IP: resolved}).IP; ip != want {
				t.Fatalf("checked %q, Caddy resolved %q (X-Forwarded-For %q)", ip, resolved, xff)
			}
		}
		if w.Code == http.StatusForbidden {
			if next.called {
				t.Fatal("blocked request reached the next handler")
			}
			return
		}
		if !next.called {
			t.Fatalf("request neither blocked nor passed: %d", w.Code)
		}
		status := next.header.Get("X-IPScanner-Status")
		if status == "" || caddyhttp.GetVar(r.Context(), VarStatus) != status {
			t.Fatalf("status header %q, var %v", status, caddyhttp.GetVar(r.Context(), VarStatus))
		}
		for name, values := range next.header {
			if !strings.HasPrefix(http.CanonicalHeaderKey(name), edge.HeaderPrefix) {
				continue
			}
			if len(values) != 1 || (status != edge.StatusOK && http.CanonicalHeaderKey(name) != "X-Ipscanner-Status") {
				t.Fatalf("visitor header %s: %q reached the next handler (status %s)", name, values, status)
			}
			if values[0] == "verified_bot" {
				t.Fatalf("forged class reached the next handler: %s", name)
			}
		}
	})
}

// FuzzLogLine checks that every core log line becomes exactly one structured entry.
func FuzzLogLine(f *testing.F) {
	f.Add(`{"ipscanner":"upstream failure","status":"error","code":0}`)
	f.Add(`{"ip":"1.2.3.4","status":"timeout","decision":"allow"}`)
	f.Add(`{"ip":"1.2.3.4","trafficClass":"human","decision":"allow","policy":{"source":"cache","version":3}}`)
	f.Add(`{"ipscanner":5,"status":null}`)
	f.Add(`not json`)
	f.Add(`[1,2,3]`)
	f.Fuzz(func(t *testing.T, line string) {
		core, logs := observer.New(zapcore.DebugLevel)
		h := &Handler{logger: zap.New(core)}
		h.logLine(line)
		entries := logs.AllUntimed()
		if len(entries) != 1 {
			t.Fatalf("%d entries for %q", len(entries), line)
		}
		var fields map[string]interface{}
		if json.Unmarshal([]byte(line), &fields) != nil {
			if entries[0].Message != line {
				t.Fatalf("plain line logged as %q", entries[0].Message)
			}
			return
		}
		if s, ok := fields["ipscanner"].(string); ok && (entries[0].Message != s || entries[0].Level != zapcore.WarnLevel) {
			t.Fatalf("message %q level %s, want %q warn", entries[0].Message, entries[0].Level, s)
		}
	})
}
