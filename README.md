# scertec

This is **scertec**, a Let's Encrypt ACME client that stores certs in [setec](https://github.com/tailscale/setec/) and a Go client library that reads those certs back out of setec at serving time via a `tls.Config.GetCertificate` hook.

It only supports ACME DNS challenges using Amazon Route53.

Directories involved:

 * `.` (package `scertec`): the client library that gets certs from setec
 * `scertecd` (package `scertecd`): the ACME client code that runs either in the foreground once or in the background as an HTTP server, keeping the certs refreshed in setec
 * `cmd/scertecd`: a little `package main` wrapper around the earlier item.
