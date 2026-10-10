# sweb.ru DNS module for Caddy

Issues certificates via ACME DNS-01 using the sweb.ru (SpaceWeb) API. Module: `dns.providers.sweb`.

## Build

    xcaddy build --with github.com/ansocket/caddy-dns-sweb

## Caddyfile

    {
        acme_dns sweb {
            login    {env.SWEB_LOGIN}
            password {env.SWEB_PASSWORD}
        }
    }
    propagation_delay   10m
    propagation_timeout 25m
    resolvers 1.1.1.1 8.8.8.8
    *.example.com {
        respond "ok"
    }

Instead of login/password you can specify `token <API token>`. For restricted access, create
a user with permissions for domains only (login in the form `sub@account`).

## Notes

- Uses the `info` and `editTxt` methods from the [API documentation](https://apidoc.sweb.ru/instructions)
  (`/domains/dns`); the token is obtained via `getToken` on `/notAuthorized/`.
- Only TXT records are supported (sufficient for DNS-01).
- The token is obtained via `getToken` and re-obtained when rejected.

## AI

This plugin is made by AI (Claude Sonnet 5.5). Just because Let's Encrypt CA didn't release DNS-Persist-01 on these non-staging servers for now, I need this plugin for wildcard certs. Use with care.