# ntpQTE

> The council of clocks, in Rust. The constellation's clock daemon:
> a hand-welded NTP client with no dependencies — the 48-byte packet is
> assembled in plain sight, the offset math is the classic RFC 5905
> formula, the consensus is the elders' median, and the drift journal is
> the fleet's own NOT-resettable clock-audit.
> UTC is the one ledger; every dogfeed row, stream cursor, and telemetry
> breath already keeps it. This crate is that discipline, made witness.

## the four moves

```bash
cargo run -- --server time.apple.com            # one query → the council line
cargo run -- --consensus time.apple.com ntp.org  # median over the elders
cargo run -- --journal --server time.apple.com  # + one drift row appended
cargo test                                      # the corridor (packet · math · consensus · journal)
```

## the math, shown (never hidden)

```
offset = ((t1 − t0) + (t2 − t3)) / 2     t0 client send · t1 server recv
delay  = (t2 − t1) + (t3 − t0)           t2 server tx · t3 client recv
```

in `Exchange::offset` / `Exchange::delay`, test-pinned with fixtures.
The consensus is the **median** over the queried elders — signed offsets
have no honest geometric mean, and a single loud (broken) peer must not
move the council.

## the journal

`~/.ntpqte/journal.jsonl` — one row per query, the ledger's grammar:

```json
{"ts":1789747742.021,"server":"time.apple.com","offset_ms":21.90,"delay_ms":15.80}
```

Append-only, never rewritten — the machine's own Clock audits, Rust
edition (the theory: `ntp-the-council-of-clocks.md` in the vault).

## why

The fleet's time was already disciplined (the 2026-09-18 check:
+21.9 ms ± 15.8 ms against Apple's pool). The crate exists so the
discipline is *rowed*, not assumed: the offset is a witness object, the
journal is its ledger row, and the council is the mean the pupil learns
from. Admissible degradation's time chapter applies: a clock must never
freeze, only degrade gracefully into the journal.

## doctrine

readability is freedom — a 48-byte packet is the whole protocol, and the
whole protocol is readable · winter is coming; the queue is the harvest;
the clock is the row · fine touch from within · vaked.dev

SPDX-License-Identifier: AGPL-3.0-only