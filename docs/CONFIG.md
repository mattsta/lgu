# Configuration

## Purpose

This document describes LGU’s detector configuration model, merge rules, file format, and operational guidance for adding site-specific logic safely.

LGU keeps the shipped defaults generic. They cover broad bot/crawler terms, common tool libraries, and known social preview fetcher user-agent product tokens that do not identify themselves with generic bot words. Site-specific behavior should be added through repo-level or operator-supplied config files, not by editing detector code.

Known-UA config is not the only path to classification. Behavioral detectors such as `coordinated-target-fanout` can still catch exact same-UA, same-target bursts across distinct IPs when the raw UA has no configured signature.

## Configuration Layers

LGU merges detector config in this order:

1. top-level shipped defaults in `defaults/detector-config.json`
2. first `--detector-config` file
3. second `--detector-config` file
4. additional `--detector-config` files in CLI order
5. CLI `--bot-pattern` additions

If `--no-default-detector-config` is used, step 1 is skipped.

## File Format

Detector config files are JSON.

Current schema:

```json
{
  "known_bot_any_patterns": ["syntheticcrawler", "syntheticprobe"],
  "known_bot_ua_patterns": ["syntheticexternalfetch"],
  "known_bot_referer_patterns": [],
  "payload_marker_patterns": ["(?:\\?|&)render=full(?:[&#]|$)"]
}
```

## Fields

### `known_bot_any_patterns`

Type:

- list of regex strings

Used against:

- raw user agent
- raw referer

Purpose:

- shared signatures that are meaningful in either field

### `known_bot_ua_patterns`

Type:

- list of regex strings

Used against:

- raw user agent only

Purpose:

- user-agent-only signatures that should not accidentally trip on referers

### `known_bot_referer_patterns`

Type:

- list of regex strings

Used against:

- raw referer only

Purpose:

- referer-only signatures that should not accidentally trip on user agents

### `payload_marker_patterns`

Type:

- list of regex strings

Used against:

- request path and query string

Purpose:

- define site-specific parameter or path forms that become high-signal when abused

## Validation Rules

LGU currently validates:

- the file must be valid JSON
- `known_bot_any_patterns` must be a list of strings
- `known_bot_ua_patterns` must be a list of strings
- `known_bot_referer_patterns` must be a list of strings
- `payload_marker_patterns` must be a list of strings

If validation fails, the CLI exits with an argument error.

## Merge Semantics

Merge behavior is additive.

That means:

- later files do not replace earlier arrays
- arrays are concatenated
- duplicates are allowed

Treat config layering as “append more detector knowledge,” not as a full override system.

Internally, LGU compiles each configured pattern list into a single regex union for runtime matching. The file format stays readable and one-pattern-per-item, while the hot path avoids carrying giant hand-written union blobs in config.

## CLI Examples

### Use shipped defaults only

```bash
uv run log-audit access.log
```

### Add one local config

```bash
uv run log-audit access.log --detector-config ./my-detectors.json
```

### Add multiple configs

```bash
uv run log-watch /var/log/nginx/access.log --follow --detector-config ./team-detectors.json --detector-config ./site-detectors.json
```

### Disable shipped defaults

```bash
uv run log-audit access.log --no-default-detector-config --detector-config ./custom-only.json
```

### Add one-off patterns

```bash
uv run log-audit access.log --bot-pattern 'curl/[0-9.]+' --bot-pattern 'wget'
```

## Design Guidance

### Keep shipped defaults generic

Good for shipped defaults:

- common crawlers
- feed readers
- generic script clients

Bad for shipped defaults:

- your site name
- your content taxonomy
- your one-off abusive IP fragments
- your private feature parameters

### Use payload markers sparingly

Good candidates:

- expensive render modes
- preview views
- internal analysis or export toggles

Bad candidates:

- every benign query parameter
- broad patterns that match most user traffic

### Prefer behavior over giant signature lists

If you find yourself needing huge custom signature piles, first ask whether:

- a behavior detector is missing
- a threshold is weak
- a cross-IP campaign detector should be improved

## Example Configs

### Generic crawler additions

```json
{
  "known_bot_any_patterns": ["syntheticcrawler", "syntheticprobe"],
  "known_bot_ua_patterns": ["syntheticexternalfetch"],
  "known_bot_referer_patterns": [],
  "payload_marker_patterns": []
}
```

### Site-specific feature abuse markers

```json
{
  "known_bot_any_patterns": [],
  "known_bot_ua_patterns": [],
  "known_bot_referer_patterns": [],
  "payload_marker_patterns": [
    "(?:\\?|&)preview=true(?:[&#]|$)",
    "(?:\\?|&)render=full(?:[&#]|$)",
    "(?:\\?|&)format=debug(?:[&#]|$)"
  ]
}
```

## Operational Safety

## Optional Provider Range Sources

Provider IP range data is optional and intentionally not bundled with LGU. Operators can point LGU at one or more local datasets:

```bash
uv run log-audit access.log --provider-ranges ./priv/cloud-provider-ip-addresses --summary
```

The provider loader uses a source-adapter registry so LGU is not tied to one external repository format. Built-in adapters support:

- `plain-cidr-text`: one CIDR per line, provider inferred from suffix-aware filenames such as `synthetichost_ips_merged_v4.txt`, simple filenames such as `synthetichost.txt`, or a parent directory when a directory adapter is reading provider folders
- `unified-csv`: records with fields such as `cidr`, `provider`, `service`, and `region`
- `unified-json`: list or object-wrapped records with CIDR/provider fields
- `cloud-provider-ip-addresses`: a local checkout of that repository shape

Useful controls:

- `--provider-source-format`: optional override for a specific adapter; omitted means auto-detect
- `--provider-include`: load only selected providers
- `--provider-exclude`: omit selected providers
- `--provider-watch`: opt in to provider-hosted activity proofs for selected providers
- `--exclude-provider-traffic`: treat every request matching a loaded provider range as filtered traffic

To remove provider-hosted traffic from filtered output, load the optional local checkout and turn on explicit provider traffic exclusion:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --exclude-provider-traffic
```

With no output-mode flag, this keeps the normal grouped recent view and removes provider-hosted ranges from that result list.

For exact original log-line replay of the surviving rows, add `--raw-filtered-lines`:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --exclude-provider-traffic \
  --raw-filtered-lines
```

To preview the rows that would be removed:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --exclude-provider-traffic \
  --bots-only \
  --summary
```

To limit exclusion to selected providers, load only those normalized provider names:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --provider-include aws \
  --provider-include digitalocean \
  --provider-include oracle \
  --exclude-provider-traffic
```

The `--provider-watch` value can still be repeated with specific normalized provider names instead of `'*'` for thresholded provider-hosted activity detection. That rule requires request count, unique path count, and existing score thresholds; loading provider ranges alone only enriches reports unless `--exclude-provider-traffic` is set.

Provider attribution is enrichment by default. It should not be treated as proof of abuse on its own, especially for CDN, relay, and shared-egress providers, unless the operator explicitly chooses provider traffic exclusion for that run.

Provider-related combinations:

| Intent                                                      | Flags                                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| enrich grouped view with provider labels only               | `--provider-ranges PATH`                                                             |
| threshold provider-hosted activity for watched providers    | `--provider-ranges PATH --provider-watch NAME`                                       |
| remove all loaded provider ranges from default grouped view | `--provider-ranges PATH --exclude-provider-traffic`                                  |
| replay exact raw survivor lines after provider removal      | `--provider-ranges PATH --exclude-provider-traffic --raw-filtered-lines`             |
| preview removed provider lines in grouped form              | `--provider-ranges PATH --exclude-provider-traffic --bots-only`                      |
| preview removed provider lines as raw log lines             | `--provider-ranges PATH --exclude-provider-traffic --raw-filtered-lines --bots-only` |
| remove only selected providers                              | `--provider-ranges PATH --provider-include NAME --exclude-provider-traffic`          |

Provider names, service names, and region names are normalized to lower-case before filtering and lookup. Custom provider sources can be registered by implementing the `ProviderRangeSource` protocol in `src/lgu/provider_ranges.py`: expose a unique `name`, a `can_load(path)` probe, and a `load(path)` method that yields normalized CIDR records. Registration order controls auto-detection precedence, and operators can bypass auto-detection with `--provider-source-format`.

### Regex safety

Avoid:

- catastrophic backtracking
- overly broad `.*` style expressions
- patterns that unintentionally match normal browsers

Prefer:

- narrow literal fragments
- anchored or specific forms where practical

### Start in audit mode

Before using new config in live automation:

1. run `log-audit --summary`
2. inspect `log-audit --bots-only`
3. review proof details
4. only then feed the same config into `log-watch`

## Current Limitations

The config model intentionally does not yet support:

- allowlists
- ASN policies
- weighted signatures
- per-detector enable/disable toggles
- different action policies per detector family
