# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0]

### Fixed

- The CLI did nothing when run through the npm bin or on Windows, and exited
  `0` ("accepted") for any input.
- A `200` response that was not a range body (captive portal, proxy, WAF) read
  as "zero matches", so every password was accepted, even under `fail-closed`.
- The request timeout covered the headers only; a stalled body hung `check()`.
- Options explicitly set to `undefined` overrode the defaults
  (`errorPolicy: undefined` behaved as fail-closed), and `NaN` values made the
  cache unbounded.

### Changed

- Error messages no longer include the hash prefix.
- `RangeLookupError` has a stable `code`: `timeout`, `network`, `http`,
  `malformed` or `invalid-input`.
- The CLI exits `3` when the API is unreachable under fail-open.
- Numeric and policy options are validated at construction time.
- Minimum supported runtime is Node 20.

### Added

- `scripts/demo-server.mjs`, a local range API for a reproducible demo.
- `SECURITY.md` with the threat model.

## [0.1.0]

- Initial version.
