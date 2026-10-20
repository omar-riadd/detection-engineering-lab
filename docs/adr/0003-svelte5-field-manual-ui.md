# ADR 0003: Svelte 5 Runes & "Field Manual" Design System

## Status
Accepted

## Context
Security operations dashboards and detection engineering portals are often cluttered with generic CSS frameworks, rounded cards, animations, and heavy JavaScript runtimes that distract from technical data density. SOC analysts and detection engineers require high information density, precise typography, terminal styling, and minimal bundle sizes.

## Decision
We chose **Svelte 5 with Runes** paired with a custom **"Field Manual"** design system:
1. **Svelte 5 Runes**: We utilize fine-grained reactive primitives (`$state`, `$derived`, `$effect`, `$props`) providing compiler-optimized reactivity with zero virtual DOM overhead and minimal bundle size (< 110 KB JS for the entire application).
2. **Field Manual Aesthetic**:
   - Zero rounded corners (`border-radius: 0`) across all cards, badges, buttons, and inputs.
   - Warm newsprint paper palette (`#f5f0e8`, `#ede8d8`) with stark archival ink accents (`#1a1812`, `#4a4538`).
   - Monospace typography (`JetBrains Mono`, `Courier New`) for high data readability and terminal alignment.
   - Structured ASCII status indicators: `[PASS]`, `[FAIL]`, `[SYNCED]`, `[DETECTED]`.

## Consequences
- **Positive**: Extremely fast build times (< 1s via Vite) and minuscule network payload (under 37 KB gzipped).
- **Positive**: High data density suited for complex security telemetry (ATT&CK heatmaps, D3FEND mappings, raw YAML/XML diffs, and live logs).
- **Positive**: Distinctive visual branding that stands out during technical interviews and hiring manager evaluations.
