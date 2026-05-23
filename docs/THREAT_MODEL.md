# Threat Model

## Purpose

This document defines what LGU, the Log Ghoul Unmasker, is designed to detect, where its evidence comes from, and where its limits begin.

LGU is an access-log behavior analysis system. It reasons from the fields present in server access logs and should be understood as an operational classifier, not an attribution engine.

## Security Objective

LGU is designed to help operators:

- separate plausibly human browsing from obviously automated access
- detect disguised crawlers that do not self-identify honestly
- detect distributed crawl campaigns that hide behind many IPs
- detect parameter mutation and probing behavior in time to react
- feed higher-confidence alert events into other systems such as fail2ban

The system is optimized for operational usefulness, not for perfect detection of every automated actor.

## Protected Assets

LGU protects:

- service capacity
- content access policy
- operator attention
- visibility into real reader traffic
- the trustworthiness of “recent traffic” inspection
- downstream ban automation that needs better signals than raw access logs

## In-Scope Adversaries

### Honest or semi-honest bots

Examples:

- feed readers
- uptime checks
- declared crawlers
- simple script clients

These are usually handled by configurable known-bot pattern matching.

### Single-IP disguised crawlers

Examples:

- broad archive walkers using browser-like UAs
- paced fetchers that avoid obvious bursts
- bots with blank or trivially repeated referers

LGU targets these with:

- burst detection
- fast streak detection
- paced sweep detection
- serial sweep detection
- periodic poller detection

### Identity-manipulating single-IP actors

Examples:

- same-IP rapid UA switching
- rotating UAs from one origin
- same-second twin requests with different UAs

LGU targets these with:

- `rapid-ua-switch`
- `rotating-ua`
- `same-second-ua-swap`

### Distributed crawlers and swarm campaigns

Examples:

- many IPs sharing one UA and sweeping path ranges
- distributed campaigns that keep per-IP rates low

LGU targets these with:

- `coordinated-ua`
- `payload-campaign`

### Payload fuzzers and active probes

Examples:

- parameter mutation
- malformed referers
- injection-style probes
- abuse of site-specific feature or rendering parameters

LGU targets these with:

- payload marker classification
- `payload-fuzzer`
- injection detection
- referer-junk detection
- distributed payload-campaign detection

## Out of Scope or Weakly Covered

LGU is not strong against:

- extremely low-and-slow distributed crawlers that stay below all local and cross-IP thresholds
- attacks whose distinguishing signals are absent from access logs
- perfect human-behavior mimicry
- exact actor attribution
- network-reputation or ASN enforcement
- provider-aware enforcement beyond explicit operator-supplied range enrichment

## Trust Boundaries

LGU assumes:

- access logs are captured accurately enough to parse
- timestamps are meaningful
- path, UA, and referer fields are present and not systematically truncated
- detector config files are trusted local inputs

LGU does not assume:

- IPs are stable identities
- UAs are truthful
- referers are truthful

In fact, much of the detector design exists because those fields are often deceptive.

## Primary Signal Families

LGU relies on five major signal families:

- signature
- rate
- sequence
- mutation
- coordination

### Signature

Examples:

- `curl`
- `python-requests`
- feed readers

Strength:

- cheap and precise when present

Weakness:

- easy to evade

### Rate

Examples:

- many requests in a short window
- many HEADs in a short window

Strength:

- catches obvious abuse quickly

Weakness:

- evadable by slower crawlers

### Sequence

Examples:

- strict serial archive walking
- repeated adjacent path pairs
- path diversity under constrained timing

Strength:

- often stronger than raw rate alone

Weakness:

- some legitimate scripted consumers can resemble it

### Mutation

Examples:

- same-page parameter mutation
- malformed referers
- injection-like payloads
- same-second identity switching on mutation twins

Strength:

- strong evidence of active probing

Weakness:

- depends on site-specific payload markers being configured sensibly

### Coordination

Examples:

- one UA spread across many IPs and many paths
- one payload abuse family expressed across many IPs

Strength:

- catches actors hiding below per-IP thresholds

Weakness:

- depends heavily on windowing and truncation choices

## False Positive Risks

Important false-positive classes include:

- legitimate scripted readers
- internal monitors
- shared proxy or NAT traffic
- privacy-preserving human users with unusual UAs or referers
- very fast but real humans on small, tightly-linked content sets

LGU’s design response is:

- preserve proof details
- keep grouped suspicious views readable
- expose summaries instead of only enforcing silently

## Non-Goals

LGU is not trying to be:

- a WAF
- a firewall manager
- a user identity system
- an attribution engine
- a browser fingerprinting platform
- a perfect detector of all machine traffic

Its role is narrower:

> turn access logs into better operational judgments about likely-human and likely-abusive traffic

## Summary

LGU is strongest where adversaries leak one or more of:

- timing regularity
- traversal regularity
- identity instability
- mutation behavior
- distributed coordination

It is weakest where:

- the access log does not contain the distinguishing signal
- the adversary is sufficiently low-rate and distributed
- human and machine behavior are genuinely hard to separate from server-side evidence alone
