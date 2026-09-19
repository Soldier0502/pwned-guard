# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/Soldier0502/pwned-guard/security/advisories/new).
Do not open a public issue. You should get a first answer within a week.

Only the latest published version is supported.

## Threat model

`pwned-guard` sits in the sign-up and password-change path of someone else's
application. It must never make that path less safe than it was without it.

### What leaves the process

- The first 5 hex characters of the password's SHA-1, in the request URL.
- The configured `User-Agent`.

Nothing else. The password, the full hash and any user identifier stay local.

### What k-anonymity does and does not give you

It hides *which* password you asked about among the several hundred that share
the prefix. It does not hide the prefix itself: whoever operates or observes the
range endpoint learns 20 bits of the hash.

- Error messages never contain the prefix, because errors tend to be logged
  next to a user identifier.
- `Add-Padding` is sent by default, so the response size does not reveal how
  many real entries the prefix has.
- If the 20 bits matter to you, point `endpoint` at a mirror you host.

### The range endpoint is not trusted to be well-formed

A captive portal, corporate proxy or WAF can answer `200 OK` with an HTML page.
Treating that as "zero matches" would accept every password, and would do so
even under `fail-closed`. Parsing is therefore strict: a body that is not made
of `SUFFIX:COUNT` lines, or that is empty, is a lookup failure (`code:
"malformed"`) and is never cached. The timeout covers the body as well as the
headers.

The endpoint can still lie in a well-formed way (a hostile mirror can answer
"not found" for everything). Use HTTPS and an endpoint you trust.

### Fail-open is the default, on purpose

When the lookup fails the password is accepted unless you choose
`errorPolicy: "fail-closed"`. A breach check is a second line of defence; taking
sign-ups down with a third-party API is usually the worse outcome. If you keep
the default, alert on `source: "error"` results: a sustained failure rate means
the check is silently off. The CLI exits with `3` in that case, never `0`.

### Out of scope

- Weak passwords that have never appeared in a public breach. Use `minLength`
  and `localBlocklist`.
- Password storage. SHA-1 is used only because the corpus is keyed by it.
- Timing side channels in the suffix comparison: it happens locally, against
  data the caller already holds.
