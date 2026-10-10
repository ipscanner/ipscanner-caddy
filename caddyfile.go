package ipscanner

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("ipscanner", parseCaddyfile)
	// Before basic_auth: after header, redir and rewrites, ahead of auth,
	// reverse_proxy and file_server. No global "order" line needed.
	httpcaddyfile.RegisterDirectiveOrder("ipscanner", httpcaddyfile.Before, "basic_auth")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Handler)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens:
//
//	ipscanner [<matcher>] {
//	    api_key       <key>
//	    api_url       <url>
//	    site_id       <site_...>
//	    mode          monitor|enforce
//	    block_classes <class...>
//	    timeout       <duration>
//	    cache_ttl     <duration>
//	    cache_size    <entries>
//	    policy_ttl    <duration>
//	    skip_paths    <regexp>|none
//	    block_message <text>
//	    debug
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		name := d.Val()
		switch name {
		case "api_key", "api_url", "site_id", "mode", "skip_paths", "block_message":
			var value string
			if !d.Args(&value) {
				return d.ArgErr()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			switch name {
			case "api_key":
				h.APIKey = value
			case "api_url":
				h.APIURL = value
			case "site_id":
				h.SiteID = value
			case "mode":
				h.Mode = value
			case "skip_paths":
				h.SkipPaths = value
			case "block_message":
				h.BlockMessage = value
			}
		case "block_classes":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.BlockClasses = append(h.BlockClasses, args...)
		case "timeout", "cache_ttl", "policy_ttl":
			var value string
			if !d.Args(&value) {
				return d.ArgErr()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(value)
			if err != nil {
				return d.Errf("%s: %v", name, err)
			}
			switch name {
			case "timeout":
				h.Timeout = caddy.Duration(dur)
			case "cache_ttl":
				h.CacheTTL = caddy.Duration(dur)
			case "policy_ttl":
				h.PolicyTTL = caddy.Duration(dur)
			}
		case "cache_size":
			var value string
			if !d.Args(&value) {
				return d.ArgErr()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return d.Errf("cache_size: %v", err)
			}
			h.CacheSize = n
		case "debug":
			args := d.RemainingArgs()
			switch {
			case len(args) == 0:
				h.Debug = true
			case len(args) == 1:
				b, err := strconv.ParseBool(args[0])
				if err != nil {
					return d.Errf("debug: %v", err)
				}
				h.Debug = b
			default:
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective %q", name)
		}
	}
	return nil
}

// Interface guard.
var _ caddyfile.Unmarshaler = (*Handler)(nil)
