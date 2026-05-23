# Changelog

## Unreleased

### Added

- Standard `uv` project packaging with installable `log-audit` and `log-watch` entrypoints
- Release-grade docs:
  - `ARCHITECTURE.md`
  - `THREAT_MODEL.md`
  - `DETECTORS.md`
  - `CONFIG.md`
  - `OPERATIONS.md`
  - `PERFORMANCE.md`
  - `TESTING.md`
  - `CONTRIBUTING.md`
- Example site-specific detector config
- MIT license
- `tests/` suite covering live transitions, distributed detector degradation, and batch execution equivalence
- `tight-multifetch` and `cadenced-repeat` proof detectors for compact synthetic fetch clusters and long-gap scheduled same-path repeats
- Near-hour two-hit shortcut thresholds for `cadenced-repeat` so sparse scheduled refetches can be categorized without waiting for a third hit
- Synthetic scenario DSL, sanitizer, probe, coverage matrix, and catalog gate for detector proof workflows
- Detector catalog documenting proof kinds, threshold arguments, config dependencies, and live coverage requirements
- Optional provider IP range enrichment through pluggable local source adapters
- Explicit `--exclude-provider-traffic` mode for removing loaded provider-hosted ranges from filtered outputs
- Clear `--raw-filtered-lines` output-mode flag for exact raw log-line replay
- Default known-UA coverage for social preview fetchers whose user agents omit generic bot/crawler terms
- Exact-UA same-target distributed fanout mode under `coordinated-target-fanout` for tight cross-IP bursts
- `asset-primed-probe` proof detector for browser-like page dependency loads followed by exposed-file probing
- Local and CI detector-quality gate covering compile checks, linting, scenario catalog coverage, and pytest
- Local registry datasets as the first whois source: `lgu-whois-data sync|info|lookup` downloads RIPE NCC's bulk database dumps (conditional, atomic), parses the RPSL as a stream, and builds a read-only SQLite index of flattened most-specific ownership segments; `log-audit` consults it before the cache and live RDAP (`--whois-data`), with placeholder objects for non-managed space excluded; datasets are used whatever their age
- `lgu-whois-probe crosscheck` (live, or offline `--from-evidence`) and `entities` for validating dataset answers and ownership parsing against recorded RDAP responses
- `lgu-whois-probe` for validating RDAP pacing from recorded registry evidence (`burst`, `replay --check`, `explain`, `summary`) with a persistent JSONL evidence log
- `lgu-whois-probe verify-cache` (live: cached answers vs the registries', `--fix` to replace diverged ones) and `evict` (offline: drop cached answers for IPs or ranges while keeping pacing state and recorded blocks), with an operator runbook in `OPERATIONS.md`; `lgu-whois-data statuses` measures which registration statuses hold smaller registrations
- Detector sweep fixtures for threshold boundary variants
- End-to-end detector validation harness covering compile checks, catalog coverage, threshold sweeps, synthetic-data hygiene, linting, and pytest from one command
- Scenario execution, schema validation, unexpected-output drift checks, and catalog-backed sweep coverage metadata in the detector validation gate
- Detector confidence report and scenario intake workflow for example-driven detector development
- Heuristic and optional-provider detector coverage in the scenario catalog gate
- Threshold boundary sweeps for heuristic and provider-hosted activity rules, with policy-level deferred configuration knobs
- Additional proof threshold sweeps for repeated-pair gap, tight multi-fetch, cadenced-repeat, and fast-streak path diversity boundaries
- Policy-backed threshold sweeps for all numeric detector catalog arguments, including revisit, UA rotation, periodic polling, serial sweep, payload fuzzer, UA switch, coordinated UA, target fanout, and payload campaign rules
- Stricter detector validation that fails on any generated confidence-report task and rejects incomplete or inconsistent sweep-policy threshold classifications
- `low-context-fanout` and `low-context-revisit` proof detectors for distributed or repeated same-target content fetches with only direct/root referer context
- `self-referer` proof detector for clients that send the exact URL being fetched as their own referer across several distinct targets
- `org` line in the grouped recent view: cached, rate-limited RDAP (whois) lookups of the registered owner of each IP block
- Structural fake-UA rules in the shipped detector config: non-browser UA shapes, impossible Chrome builds, stale desktop Chrome and Firefox, and browser-shaped automation tokens
- `subnet-sweep` proof detector for residential/proxy-pool botnets that run one exact UA across many hosts in one network prefix (`/22` IPv4, `/48` IPv6 by default), walking many distinct pages with direct/root referers at a pace too slow for `coordinated-ua`
- Reverse DNS `ptr` line under each IP in the grouped recent view, backed by a shared on-disk IP-to-PTR cache (`--ptr-cache`, `$LGU_PTR_CACHE`, or `$XDG_CACHE_HOME/lgu/ptr-cache.json`) with `--no-reverse-dns`, `--ptr-resolver`, `--ptr-cache-ttl`, and `--ptr-timeout` controls
- Non-banning texture signals for residential proxy crawlers: `machine-path`, `exposure-probe`, `suspect-ua`, `protocol-mismatch`, `uncompressed-fetch`, and `redirect-ip-hop`. They hide traffic from the human view, reach at most `suspect` live, and yield to browser evidence (except `exposure-probe`)
- `suspect_ua_patterns`, `machine_path_patterns`, and `probe_path_patterns` detector config fields, with shipped defaults
- Visit tiers from browser evidence: `visit=confirmed|split|unconfirmed` in the grouped view, `visitor_breakdown` in `--summary`, and `--confirmed-only`. `split` pairs a prefetched page with the visitor who followed from another address
- `why` line in the `--bots-only` grouped view naming the proofs that hid each client
- `--trusted-proxy` to read the real client from the trailing forwarded log field, only for peers in listed networks
- HTTP protocol version and response size retained on parsed rows
- `stale-browser` signal that measures Chrome-family and Firefox versions against versions seen rendering pages in the log, replacing fixed cutoffs for those browsers
- `sole_signal_ips` in `--summary` and `--sole-signal KIND` to review clients hidden by exactly one signal
- `tests/decision_diff.py` to compare banned addresses between two `log-watch` runs
- `--show-path` to narrow reports after analysis, so detectors and visit labels keep the full traffic picture, plus a stderr note when no reported client has browser evidence

### Changed

- Detector defaults moved into packaged JSON config instead of shipped hardcoded detector data
- Payload-marker handling generalized so site-specific query semantics are config-driven
- Strong proof ban policy now reads from the detector catalog instead of a local literal set
- Grouped recent view improved for readability and numbering
- `ARCHITECTURE.md` expanded with real dataflow, threat model, detector taxonomy, and future live-engine redesign

### Fixed

- A malformed referer or request path, such as a URL with a bracketed IPv4 host, no longer crashes `log-audit` or `log-watch` with an uncaught `ValueError`; any client could trigger this with one request
- `--path-include` no longer silently drops matching lines: the prefilter ignored literals under four characters, so `\.(mp3|webm)` only matched lines containing `webm`. It now applies only when every pattern is a plain literal
- `--output-format fail2ban --emit-suspects` no longer writes suspects as `action=ban`, which the shipped filter would have banned
- `coordinated-ua` no longer treats browser page-asset fetches as a sweep. Reduced user agents make unrelated visitors identical, so a few people loading one page could be hidden, and banned live
- HTML and other document paths are classified as pages rather than assets, so distributed fanout and subnet detectors no longer skip them
- Invalid `--path-include` and `--path-exclude` regexes are usage errors instead of tracebacks
- Grouped and live user agent summaries name Edge, Opera, and Samsung Internet instead of reporting them as Chrome
- Whois pacing no longer turns one throttle response into a run-long pause: a 429 without `Retry-After` backs off 2s doubling (not a fixed 5 minutes), short pauses are slept and the IP retried, self-imposed spacing is never deferred, a bare 403 is reported as access denied rather than a rate limit, refusals after redirects are charged to the registry that sent them, and the refusal behind each persisted pause is recorded
- RIPE NCC access blocks (`%ERROR:201: access denied`, sent as HTTP 429) are classified as blocks rather than throttles: never retried, persisted until 00:00 UTC (temporary) or until cleared with `lgu-whois-probe clear-denial` (permanent), honored for addresses redirected to RIPE, and refused by `lgu-whois-probe burst` without `--force`. Corrected the docs' claim that RIPE network lookups return no personal data; they embed contact objects that count toward RIPE's 1,000-per-day cap
- RDAP ownership no longer reports RIPE maintainer accounts (registrants whose vCard name is their own handle, e.g. `*-NIC`, `*-MNTNER`, `*MNT-1`) as the network owner; only organisations count, else the network name is shown
- Registry placeholder answers (APNIC's all-of-IPv4 `IANA-BLOCK`, RIPE's `IANA-BLK` and `NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK`, or anything wider than an IPv4 /8 or IPv6 /12) are no longer cached by range. One such answer had labelled every later IPv4 visitor `IANA-BLOCK [APNIC]` and stopped them being queried for the cache TTL. They are rejected from live answers, the cache file (cleaned at the next save) and local datasets; the IP shows `? no owner: ...` and is retried after a day. `lgu-whois-probe explain` lists such records in a cache, `entities` marks them, and the new `lgu-whois-probe ask REGISTRY IP...` shows one registry's answer and whether it would be used
- Whois answers that are allocations no longer answer for other addresses in their range. RDAP returns the most specific registration for the queried IP; reusing an ISP allocation for its neighbours showed the ISP for addresses the registry assigns to a customer. Only end-user assignments (types containing `ASSIGN`; measured on RIPE's full database, 0.004% of assignments hold another registration against 2-72% per allocation status) are cached by range; other answers are cached per IP. Range records cached by earlier releases carry no type and are asked again as their IPs are shown; the next save drops them
- RIPE NCC lookups are held to 150 answers per 24 hours, under the AUP's 1,000 personal-data objects per day; request history for each registry is kept as long as its longest limit window
- Reverse DNS no longer caches a failed query as "no PTR": `dig` runs with `+comments`, and only NOERROR or NXDOMAIN responses (or host-not-found/no-data from the system resolver) are cached; SERVFAIL, REFUSED, timeouts, and try-again errors are asked again next run
- `--bots-only` mode semantics
- `--emit-suspects` live suppression behavior
- stale live IP state retention
- distributed detector overload behavior so key detectors degrade instead of disappearing
- multiprocessing payload-marker configuration hazard
- repeated known-bot regex compilation in hot paths
- live engine architecture to use incremental per-IP state and incremental distributed windows instead of rescanning retained global history each event
- live operator status output and stronger suspicious-summary ordering
- runtime detector configuration to use explicit runtime objects instead of process-global mutable detector state

### Known limitations

- distributed overload handling is still recency-biased within bounded windows
- LGU is still tuned for scoped operator workflows rather than arbitrary unbounded event rates
