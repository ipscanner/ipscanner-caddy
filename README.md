# IPScanner for Caddy

Caddy module that checks visitors with [IPScanner](https://ipscanner.io) before a request reaches your site, and blocks bots, Tor, VPN and proxy traffic by policy.

It makes the same edge check as the [Cloudflare Worker](https://github.com/ipscanner/ipscanner-cloudflare) and the [WordPress plugin](https://github.com/ipscanner/ipscanner-wordpress) (`POST /v1/edge/check`, 2 request units per uncached visitor) and can follow a site's policy from the [dashboard](https://ipscanner.io/dashboard/sites). Module ID `http.handlers.ipscanner`, Caddyfile directive `ipscanner`.

## Install

Build Caddy with the module:

```sh
xcaddy build --with github.com/ipscanner/ipscanner-caddy
```

Or pick `github.com/ipscanner/ipscanner-caddy` on [caddyserver.com/download](https://caddyserver.com/download). With Docker:

```dockerfile
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/ipscanner/ipscanner-caddy

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Requires Caddy 2.8 or later. Check with `caddy list-modules | grep ipscanner`.

## Usage

Create an API key at [ipscanner.io](https://ipscanner.io) and a site in the [dashboard](https://ipscanner.io/dashboard/sites), then:

```caddyfile
example.com {
	ipscanner {
		site_id site_...
	}
	reverse_proxy localhost:8080
}
```

The key is read from `IPSCANNER_API_KEY` in Caddy's environment. Mode and per class policy then come from the dashboard, and changes apply without a reload.

The directive is ordered before `basic_auth`, so no global `order` line is needed: it runs after `header`, `redir` and rewrites, and before authentication, `reverse_proxy` and `file_server`. A matcher limits it to some paths: `ipscanner /app/* { ... }`.

Without a site, the Caddyfile sets mode and blocked classes:

```caddyfile
ipscanner {
	mode enforce
	block_classes malicious_automation tor
}
```

## How it works

| | |
|---|---|
| Classes | `human`, `verified_bot`, `ai_agent`, `malicious_automation`, `tor`, `vpn`, `proxy`, `hosting`, `relay` |
| Without `site_id` | `mode` (default `monitor`) and `block_classes` (default `malicious_automation`) from the Caddyfile. The network class counts too, so blocking `vpn` also blocks a bot on a VPN. |
| With `site_id` | Mode and per class policy (`allow`, `flag`, `block`) from `GET /v1/sites/{id}/policy`, cached 30 s, last good policy kept for 24 h if a refresh fails. `mode monitor` keeps the module in monitor mode whatever the dashboard says. |
| Always pass | Verified crawlers, `OPTIONS`, private and loopback addresses, paths matching `skip_paths`. |
| Cache | One check per visitor (site, IP, user agent) per 10 minutes, in memory, bounded to 10000 entries. A config reload starts with an empty cache. |
| Fail open | One 1.5 s budget for verdict and policy. On a timeout or error the request passes and checks pause for 30 s (5 minutes on 401, 402, 403 or 429). |
| Blocked | 403 page with Caddy's request ID. `monitor` never blocks: the outcome is `would_block` or `would_flag`. |
| Visitor IP | The client IP Caddy resolved (`{client_ip}`), so the server's `trusted_proxies` apply. See [Client IP](#client-ip). |
| Debug | `debug` adds `X-IPScanner-Status`, `-Class` and `-Action` to responses and logs every decision. |

Incoming `X-IPScanner-*` headers are removed, so clients cannot send a verdict of their own. Requests to the API send `Authorization: Bearer <key>`, `X-IPScanner-Source: caddy` and `User-Agent: ipscanner-caddy/<version>`.

## Configuration

| Subdirective | Default | Description |
|---|---|---|
| `api_key` | `{env.IPSCANNER_API_KEY}` | API key. Placeholders work: `{env.NAME}`, `{file./run/secrets/ipscanner}`. Without a key every request passes with status `skipped`. |
| `site_id` | | Dashboard site (`site_...`). Mode and policy then come from the dashboard. |
| `mode` | `monitor` | `monitor` or `enforce`. With `site_id` only `monitor` has an effect. |
| `block_classes` | `malicious_automation` | Classes blocked in enforce mode without `site_id`. Any of `malicious_automation`, `ai_agent`, `tor`, `vpn`, `proxy`, `hosting`, `relay`, or `none`. |
| `timeout` | `1.5s` | Budget for one check. |
| `cache_ttl` | `10m` | Verdict cache per site, IP and user agent. |
| `cache_size` | `10000` | Verdict cache entries. |
| `policy_ttl` | `30s` | Site policy cache. |
| `skip_paths` | static assets | Case insensitive regex on the path as the visitor sent it. `none` checks every path. |
| `block_message` | `Blocked by IPScanner edge guard.` | Text of the 403 page. |
| `debug` | off | Response debug headers and one log line per decision. |
| `api_url` | `https://ipscanner.io` | API base URL. |

The default `skip_paths` is `robots.txt`, `sitemap.xml`, `favicon.ico` and files ending in `.css`, `.js`, `.mjs`, `.map`, images, fonts, `.mp4` and `.webm`.

JSON config, the same fields:

```json
{
	"handler": "ipscanner",
	"site_id": "site_...",
	"timeout": "1.5s",
	"block_classes": ["malicious_automation", "tor"]
}
```

## Client IP

The module uses Caddy's resolved client IP and does not read `X-Forwarded-For` itself. Without `trusted_proxies` that is the peer address. Behind a load balancer or CDN, trust it in the global options:

```caddyfile
{
	servers {
		trusted_proxies static 10.0.0.0/8
		trusted_proxies_strict
	}
}
```

`trusted_proxies_strict` takes the rightmost untrusted address, as the Worker and the WordPress plugin do, so a visitor cannot prepend a fake hop. Behind Cloudflare, trust the [Cloudflare ranges](https://www.cloudflare.com/ips/) and add `client_ip_headers CF-Connecting-IP`.

## Headers

Added to the request for the next handler and the upstream:

| Header | Example |
|---|---|
| `X-IPScanner-Status` | `ok`, `error`, `timeout`, `backoff` or `skipped` |
| `X-IPScanner-Class` | `human`, `verified_bot`, `vpn`, ... |
| `X-IPScanner-Action` | `allow`, `flag`, `block`, `would_flag`, `would_block` |
| `X-IPScanner-Network-Class` | `residential_clean`, `hosting`, `vpn`, `tor`, ... |
| `X-IPScanner-Anonymized` | `true` or `false` |
| `X-IPScanner-Risk` | `0` to `100` |
| `X-IPScanner-Country` | `DE` |
| `X-IPScanner-Site` | `site_...`, set with `site_id` |

When a check fails or is skipped, only `X-IPScanner-Status` is set.

## Placeholders

| Placeholder | Values |
|---|---|
| `{http.vars.ipscanner.status}` | `ok`, `error`, `timeout`, `backoff`, `skipped` |
| `{http.vars.ipscanner.class}` | Traffic class, set when the status is `ok` |
| `{http.vars.ipscanner.action}` | `allow`, `flag`, `block`, `would_flag`, `would_block` |

For access logs and matchers after the directive:

```caddyfile
log_append ipscanner_class {http.vars.ipscanner.class}
log_append ipscanner_action {http.vars.ipscanner.action}

@flagged vars ipscanner.action flag
request_header @flagged X-Review 1
```

## Develop

```sh
go test -race ./...
IPSCANNER_KEY_FILE=/path/to/key IPSCANNER_E2E_SITE_HELPER=/path/to/site.cjs sh test/e2e/run.sh
```

The end to end run builds Caddy with `xcaddy` in the `caddy:2.11-builder` image, starts it with Docker Compose in front of an echo upstream and sends requests as different visitors. It needs an API on `IPSCANNER_API_URL` (default `http://localhost:3050`) and a helper script that upserts test sites and lists request log rows.

The decision logic lives in [ipscanner-edge-go](https://github.com/ipscanner/ipscanner-edge-go), shared with the Traefik plugin and the forward auth gate.

API reference: [ipscanner.io/api-documentation](https://ipscanner.io/api-documentation).

## License

MIT
