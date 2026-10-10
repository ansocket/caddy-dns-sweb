// Package sweb implements a libdns provider and a Caddy module for the
// sweb.ru (SpaceWeb) DNS API, enough to solve ACME DNS-01 challenges.
package sweb

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

// Provider manages TXT records in sweb.ru DNS zones.
type Provider struct {
	// Login is the sweb.ru account login (sub-accounts: "sub@account").
	Login string `json:"login,omitempty"`
	// Password is the account password.
	Password string `json:"password,omitempty"`
	// Token is an optional pre-issued API token; used instead of login/password.
	Token string `json:"token,omitempty"`
	// BaseURL overrides the API base URL (for testing).
	BaseURL string `json:"base_url,omitempty"`

	c *client
}

func init() { caddy.RegisterModule(Provider{}) }

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.sweb",
		New: func() caddy.Module { return &Provider{} },
	}
}

// Provision sets up the module and expands placeholders.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Login = repl.ReplaceAll(p.Login, "")
	p.Password = repl.ReplaceAll(p.Password, "")
	p.Token = repl.ReplaceAll(p.Token, "")
	p.BaseURL = repl.ReplaceAll(p.BaseURL, "")
	if p.Token == "" && (p.Login == "" || p.Password == "") {
		return fmt.Errorf("sweb: either token or login and password are required")
	}
	return nil
}

// UnmarshalCaddyfile parses:
//
//	sweb {
//	    login    <login>
//	    password <password>
//	    token    <token>      # alternative to login/password
//	    base_url <url>        # optional
//	}
//
// or the shorthand `sweb <login> <password>`.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 0:
		case 2:
			p.Login, p.Password = args[0], args[1]
		default:
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			var dst *string
			switch d.Val() {
			case "login":
				dst = &p.Login
			case "password":
				dst = &p.Password
			case "token":
				dst = &p.Token
			case "base_url":
				dst = &p.BaseURL
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
			if !d.AllArgs(dst) {
				return d.ArgErr()
			}
		}
	}
	if p.Token == "" && (p.Login == "" || p.Password == "") {
		return d.Err("missing token or login/password")
	}
	return nil
}

func (p *Provider) client() *client {
	if p.c == nil {
		p.c = &client{baseURL: p.BaseURL, login: p.Login, password: p.Password, token: p.Token}
	}
	return p.c
}

func normZone(zone string) string { return strings.TrimSuffix(zone, ".") }

// matches reports whether an API record name refers to the relative name rel
// within zone. The API may return the apex as "@", "" or the zone itself, and
// subdomains either relative or fully qualified.
func matches(apiName, rel, zone string) bool {
	apiName = strings.TrimSuffix(strings.ToLower(apiName), ".")
	rel = strings.ToLower(rel)
	zone = strings.ToLower(zone)
	isApex := func(n string) bool { return n == "" || n == "@" || n == zone }
	if isApex(rel) {
		return isApex(apiName)
	}
	return apiName == rel || apiName == rel+"."+zone
}

func relName(name, zone string) string {
	rel := libdns.RelativeName(name, zone+".")
	if rel == "" {
		return "@"
	}
	return rel
}

// GetRecords lists the TXT records of the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zone = normZone(zone)
	recs, err := p.client().listTXT(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, r := range recs {
		name := strings.TrimSuffix(r.Name, "."+zone)
		if name == "" || name == zone {
			name = "@"
		}
		out = append(out, libdns.TXT{Name: name, Text: r.Value})
	}
	return out, nil
}

// AppendRecords adds TXT records to the zone. Only TXT is supported.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zone = normZone(zone)
	var added []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			return added, fmt.Errorf("sweb: unsupported record type %q (only TXT)", rr.Type)
		}
		if err := p.client().addTXT(ctx, zone, relName(rr.Name, zone), rr.Data); err != nil {
			return added, err
		}
		added = append(added, rec)
	}
	return added, nil
}

// DeleteRecords removes the TXT records matching name and value.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zone = normZone(zone)
	var deleted []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			continue
		}
		rel := relName(rr.Name, zone)
		// Re-list for every deletion: record indexes shift after a delete.
		existing, err := p.client().listTXT(ctx, zone)
		if err != nil {
			return deleted, err
		}
		for _, ex := range existing {
			if ex.Value == rr.Data && matches(ex.Name, rel, zone) {
				if err := p.client().deleteTXT(ctx, zone, ex.Index); err != nil {
					return deleted, err
				}
				deleted = append(deleted, rec)
				break
			}
		}
	}
	return deleted, nil
}

var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
