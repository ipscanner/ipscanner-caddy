//go:build e2e

// Package e2e drives a real Caddy built with the module (see run.sh) against
// a real IPScanner API. Run it with run.sh, not directly.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	ipResidential = "84.128.0.1"
	ipTor         = "185.220.101.1"
	ipVPN         = "185.217.69.166"
	ipHosting     = "5.9.0.1"
	ipGooglebot   = "66.249.66.1"

	chromeUA    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	headlessUA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"
	googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	container = "ipscanner-caddy-e2e-caddy"
	source    = "caddy"
)

// Listeners, see Caddyfile.
const (
	portSite      = 18091
	portNoSite    = 18092
	portDefaults  = 18093
	portDeadAPI   = 18094
	portSlowAPI   = 18095
	portUntrusted = 18096
	portMonitor   = 18097
	portOverride  = 18098
	portSlowStub  = 18099
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func siteEnforce() string { return env("IPSCANNER_E2E_SITE", "site_caddye2e000000000001") }
func siteMonitor() string { return env("IPSCANNER_E2E_SITE_MONITOR", "site_caddye2e000000000002") }

type siteRow struct {
	PolicyVersion int     `json:"policy_version"`
	ClientVersion *string `json:"client_version"`
}

// helper runs the site helper, with retries: it talks to the database.
func helper(t *testing.T, args ...string) []byte {
	t.Helper()
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var out []byte
		out, err = exec.Command("node", append([]string{os.Getenv("IPSCANNER_E2E_SITE_HELPER")}, args...)...).Output()
		if err == nil {
			return out
		}
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("site helper %v: %v", args[:2], err)
	return nil
}

func setSite(t *testing.T, id, mode string, policy map[string]string) siteRow {
	t.Helper()
	raw, _ := json.Marshal(policy)
	var row siteRow
	if err := json.Unmarshal(helper(t, id, source, mode, string(raw)), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

type logRow struct {
	Source       string `json:"source"`
	Endpoint     string `json:"endpoint"`
	TrafficClass string `json:"traffic_class"`
	Site         string `json:"site"`
	CreatedAt    string `json:"created_at"`
}

func rows(t *testing.T, n int) []logRow {
	t.Helper()
	var out []logRow
	if err := json.Unmarshal(helper(t, "rows", source, strconv.Itoa(n)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// uniqueUA keeps verdicts of earlier runs out of every cache.
func uniqueUA(base string) string {
	return base + " e2e/" + strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.Itoa(rand.Intn(1000))
}

type echo struct {
	Code     int
	Elapsed  time.Duration
	Header   http.Header
	Body     string
	Upstream struct {
		Status  string `json:"status"`
		Class   string `json:"class"`
		Action  string `json:"action"`
		Network string `json:"network"`
		Site    string `json:"site"`
		Country string `json:"country"`
		Flagged string `json:"flagged"`
	}
}

// visit sends a request to a listener as the visitor at ip: the test client
// is a trusted proxy (private range) for every listener but :18096.
func visit(t *testing.T, port int, path, ip, ua string) echo {
	t.Helper()
	return visitXFF(t, port, path, ip, ua)
}

func visitXFF(t *testing.T, port int, path, xff, ua string) echo {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	start := time.Now()
	res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET :%d%s: %v", port, path, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	e := echo{Code: res.StatusCode, Elapsed: time.Since(start), Header: res.Header, Body: string(body)}
	if res.StatusCode == 200 {
		if err := json.Unmarshal(body, &e.Upstream); err != nil {
			t.Fatalf("upstream body %q: %v", body, err)
		}
	}
	return e
}

// warm makes one call with a long timeout, so a cold API does not make the
// first scenario fail open.
func warm(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("IPSCANNER_KEY_FILE"))
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	body, _ := json.Marshal(map[string]interface{}{"ip": ipResidential, "user_agent": uniqueUA(chromeUA), "headers": map[string]string{}})
	req, _ := http.NewRequest(http.MethodPost, env("IPSCANNER_API_URL", "http://localhost:3050")+"/v1/edge/check", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	for attempt := 1; ; attempt++ {
		res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return
			}
			err = fmt.Errorf("HTTP %d", res.StatusCode)
		}
		if attempt == 5 {
			t.Fatalf("warm up: %v", err)
		}
		time.Sleep(5 * time.Second)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
}

func TestMain(m *testing.M) {
	for _, name := range []string{"IPSCANNER_KEY_FILE", "IPSCANNER_E2E_SITE_HELPER"} {
		if os.Getenv(name) == "" {
			fmt.Fprintf(os.Stderr, "set %s (run test/e2e/run.sh)\n", name)
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

func TestE2E(t *testing.T) {
	// No API call in these: they run before the warm up.
	t.Run("static asset skipped", func(t *testing.T) {
		e := visit(t, portSite, "/assets/app.css", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "skipped" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("spoofed X-Forwarded-For from an untrusted peer is ignored", func(t *testing.T) {
		e := visit(t, portUntrusted, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "skipped" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("fail open on a dead API, then backoff", func(t *testing.T) {
		e := visit(t, portDeadAPI, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "error" || e.Elapsed > time.Second {
			t.Fatalf("%d %+v in %s", e.Code, e.Upstream, e.Elapsed)
		}
		e = visit(t, portDeadAPI, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "backoff" || e.Elapsed > 300*time.Millisecond {
			t.Fatalf("%d %+v in %s", e.Code, e.Upstream, e.Elapsed)
		}
		t.Logf("second request in %s", e.Elapsed)
	})

	t.Run("fail open on a slow API within the timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portSlowStub))
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done():
			}
		})}
		go srv.Serve(ln)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		}()
		e := visit(t, portSlowAPI, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "timeout" || e.Elapsed > 1200*time.Millisecond {
			t.Fatalf("%d %+v in %s", e.Code, e.Upstream, e.Elapsed)
		}
		e = visit(t, portSlowAPI, "/", ipTor, uniqueUA(chromeUA))
		if e.Upstream.Status != "backoff" {
			t.Fatalf("%+v", e.Upstream)
		}
	})

	// Real API from here on.
	setSite(t, siteEnforce(), "enforce", map[string]string{"tor": "block", "vpn": "flag", "verified_bot": "block"})
	setSite(t, siteMonitor(), "monitor", map[string]string{"tor": "block", "vpn": "block"})
	warm(t)

	t.Run("residential allowed with upstream and debug headers", func(t *testing.T) {
		e := visit(t, portSite, "/page", ipResidential, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "ok" || e.Upstream.Class != "human" || e.Upstream.Action != "allow" || e.Upstream.Site != siteEnforce() {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
		if e.Header.Get("X-Ipscanner-Status") != "ok" || e.Header.Get("X-Ipscanner-Class") != "human" || e.Header.Get("X-Ipscanner-Action") != "allow" {
			t.Fatalf("debug headers %v", e.Header)
		}
		t.Logf("network=%s country=%s in %s", e.Upstream.Network, e.Upstream.Country, e.Elapsed)
	})

	t.Run("tor blocked under the enforce policy", func(t *testing.T) {
		e := visit(t, portSite, "/page", ipTor, uniqueUA(chromeUA))
		if e.Code != 403 || !strings.Contains(e.Body, "Blocked by IPScanner") || e.Header.Get("X-Ipscanner-Action") != "block" {
			t.Fatalf("%d %v %q", e.Code, e.Header, e.Body)
		}
		// The block page shows Caddy's request UUID.
		if !regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`).MatchString(e.Body) {
			t.Fatalf("no request id on the block page: %q", e.Body)
		}
	})

	t.Run("flagged vpn passes with headers and vars", func(t *testing.T) {
		e := visit(t, portSite, "/page", ipVPN, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Class != "vpn" || e.Upstream.Action != "flag" || e.Upstream.Flagged != "1" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("verified crawler passes a block policy", func(t *testing.T) {
		e := visit(t, portSite, "/page", ipGooglebot, googlebotUA)
		if e.Code != 200 || e.Upstream.Class != "verified_bot" || e.Upstream.Action != "allow" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("monitor site never blocks", func(t *testing.T) {
		for _, ip := range []string{ipTor, ipVPN} {
			e := visit(t, portMonitor, "/", ip, uniqueUA(chromeUA))
			if e.Code != 200 || e.Upstream.Action != "would_block" || e.Upstream.Site != siteMonitor() {
				t.Fatalf("%s: %d %+v", ip, e.Code, e.Upstream)
			}
		}
	})

	t.Run("mode monitor in the Caddyfile overrides an enforce site", func(t *testing.T) {
		e := visit(t, portOverride, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Class != "tor" || e.Upstream.Action != "would_block" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("no site: blocked classes from the config", func(t *testing.T) {
		e := visit(t, portNoSite, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 403 {
			t.Fatalf("tor: %d %+v", e.Code, e.Upstream)
		}
		e = visit(t, portNoSite, "/", ipResidential, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Status != "ok" || e.Upstream.Action != "allow" || e.Upstream.Site != "" {
			t.Fatalf("residential: %d %+v", e.Code, e.Upstream)
		}
		e = visit(t, portNoSite, "/", ipVPN, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Class != "vpn" || e.Upstream.Action != "allow" {
			t.Fatalf("vpn: %d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("no site defaults: monitor", func(t *testing.T) {
		e := visit(t, portDefaults, "/", ipTor, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Class != "tor" || e.Upstream.Action != "allow" {
			t.Fatalf("tor: %d %+v", e.Code, e.Upstream)
		}
		e = visit(t, portDefaults, "/", ipHosting, uniqueUA(headlessUA))
		if e.Code != 200 {
			t.Fatalf("headless: %d", e.Code)
		}
		if e.Upstream.Class == "malicious_automation" && e.Upstream.Action != "would_block" {
			t.Fatalf("headless: %+v", e.Upstream)
		}
		t.Logf("headless from hosting: class=%s action=%s", e.Upstream.Class, e.Upstream.Action)
	})

	t.Run("spoofed left hop behind a trusted proxy is ignored", func(t *testing.T) {
		// trusted_proxies_strict: the rightmost untrusted hop is the visitor.
		e := visitXFF(t, portSite, "/", ipTor+", "+ipResidential, uniqueUA(chromeUA))
		if e.Code != 200 || e.Upstream.Class != "human" {
			t.Fatalf("%d %+v", e.Code, e.Upstream)
		}
	})

	t.Run("verdict cache and request log", func(t *testing.T) {
		ua := uniqueUA(chromeUA)
		since := time.Now()
		first := visit(t, portSite, "/a", ipResidential, ua)
		second := visit(t, portSite, "/b", ipResidential, ua)
		if first.Upstream.Status != "ok" || second.Upstream.Status != "ok" || second.Upstream.Class != first.Upstream.Class {
			t.Fatalf("%+v / %+v", first.Upstream, second.Upstream)
		}
		// A marker after the cached request: the log is written in order,
		// so once the marker is there a call by the second request would be.
		marker := visit(t, portSite, "/c", ipVPN, uniqueUA(chromeUA))
		if marker.Upstream.Class != "vpn" {
			t.Fatalf("marker %+v", marker.Upstream)
		}
		fresh := waitRows(t, since, 2)
		if len(fresh) != 2 {
			t.Fatalf("want the first request and the marker after %s, got %+v", since.UTC().Format(time.RFC3339Nano), fresh)
		}
		classes := map[string]bool{}
		for _, r := range fresh {
			if r.Source != source || r.Site != siteEnforce() || r.Endpoint != "/v1/edge/check" {
				t.Fatalf("row %+v", r)
			}
			classes[r.TrafficClass] = true
		}
		if !classes["vpn"] || !classes[first.Upstream.Class] {
			t.Fatalf("rows %+v", fresh)
		}
	})

	t.Run("policy change after the policy TTL", func(t *testing.T) {
		ua := uniqueUA(chromeUA)
		if e := visit(t, portSite, "/", ipTor, ua); e.Code != 403 {
			t.Fatalf("before: %d", e.Code)
		}
		start := time.Now()
		row := setSite(t, siteEnforce(), "enforce", map[string]string{"tor": "flag", "vpn": "flag", "verified_bot": "block"})
		if time.Since(start) < 2*time.Second {
			if e := visit(t, portSite, "/", ipTor, ua); e.Code != 403 {
				t.Fatalf("policy changed before the TTL: %d %+v", e.Code, e.Upstream)
			}
		}
		time.Sleep(3200 * time.Millisecond)
		e := visit(t, portSite, "/", ipTor, ua)
		if e.Code != 200 || e.Upstream.Action != "flag" || e.Upstream.Flagged != "1" {
			t.Fatalf("after the TTL (policy version %d): %d %+v", row.PolicyVersion, e.Code, e.Upstream)
		}
	})

	t.Run("client version recorded on the site", func(t *testing.T) {
		row := setSite(t, siteEnforce(), "enforce", map[string]string{"tor": "flag", "vpn": "flag", "verified_bot": "block"})
		if row.ClientVersion == nil || *row.ClientVersion != "0.1.0" {
			t.Fatalf("client_version %v", row.ClientVersion)
		}
	})

	t.Run("access log carries the vars", func(t *testing.T) {
		out, err := exec.Command("docker", "logs", container).CombinedOutput()
		if err != nil {
			t.Fatalf("docker logs: %v", err)
		}
		logs := string(out)
		if !strings.Contains(logs, `"ipscanner_class":"tor"`) || !strings.Contains(logs, `"ipscanner_action":"block"`) {
			t.Fatal("access log has no ipscanner_class / ipscanner_action fields")
		}
	})
}

// The API writes request_log in batches, usually within 5 seconds.
const flushWait = 120 * time.Second

func waitRows(t *testing.T, since time.Time, n int) []logRow {
	t.Helper()
	var fresh []logRow
	for deadline := time.Now().Add(flushWait); time.Now().Before(deadline); time.Sleep(time.Second) {
		fresh = fresh[:0]
		for _, r := range rows(t, 200) {
			if r.Site != siteEnforce() {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
			if err != nil {
				t.Fatalf("created_at %q", r.CreatedAt)
			}
			if at.After(since) {
				fresh = append(fresh, r)
			}
		}
		if len(fresh) >= n {
			// One more poll so a late extra row is seen too.
			time.Sleep(2 * time.Second)
			return waitRowsOnce(t, since)
		}
	}
	return fresh
}

func waitRowsOnce(t *testing.T, since time.Time) []logRow {
	var fresh []logRow
	for _, r := range rows(t, 200) {
		at, _ := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if r.Site == siteEnforce() && at.After(since) {
			fresh = append(fresh, r)
		}
	}
	return fresh
}
