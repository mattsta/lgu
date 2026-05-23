# Contributing

## Purpose

This document explains how to contribute to LGU without damaging its core design goals:

- explainable behavior-based detection
- generic-by-default public release quality
- strong operator usability
- shared semantics between batch and live modes

## Core Design Rules

### Keep defaults generic

Do not hardcode:

- site names
- content taxonomies
- one-off abusive IP fragments
- private query parameters

If a detector needs site-specific knowledge, it belongs in config or examples, not in shipped core logic.

### Preserve explainability

Every detector should answer:

- why did this fire
- what evidence would the operator inspect
- how would someone audit a false positive

### Preserve batch/live semantic alignment

Batch and live can have different orchestration, but they should not drift in the meaning of:

- proof kinds
- classifier thresholds
- action semantics

### Prefer behavior over giant signature piles

If a problem seems to require ever-growing ad hoc signatures, first ask whether:

- a behavior detector is missing
- a threshold is weak
- a cross-IP detector should be improved

## Code Layout

- `src/lgu/audit.py`: shared parser, aggregation, detectors, batch CLI
- `src/lgu/watch.py`: live orchestration and live CLI
- `defaults/detector-config.json`: shipped runtime detector defaults
- `examples/`: integration and config examples

## Adding a Detector

Before writing code, define:

1. scope:
   - per-row
   - per-IP
   - cross-IP
2. class:
   - heuristic
   - proof
   - reporting-only
3. evidence:
   - what fields it uses
   - what windows it needs
4. output:
   - score contribution
   - bot flag
   - `ForcedProof`
   - campaign summary
5. operator explanation
6. cost in batch and live modes

## Documentation Expectations

If you change:

- a detector
- a config field
- a live behavior or coverage semantic
- a major threshold family

then update the relevant docs:

- `DETECTORS.md`
- `CONFIG.md`
- `ARCHITECTURE.md`
- `README.md`
- `CHANGELOG.md`

## Development Workflow

Typical cycle:

1. change code
2. run compile checks
3. run focused validation
4. inspect human-readable output
5. inspect machine-readable output when relevant
6. update docs
7. update changelog
