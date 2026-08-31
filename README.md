# ELFScan

ELF security scanner in C. Finds NOP sleds and the routines that build
them, in x86 and x86-64 executables. One file, no dependencies.

```sh
make
./elfscan /usr/bin/something
./elfscan -a suspicious.bin        # scan a non-ELF file raw
./elfscan -v -t 16 -s 32 *.so      # more sensitive
```

## What it reports

| finding | meaning |
|---|---|
| `[NOP_SLED]` | a run of real NOP instructions, prefixes and all |
| `[SLIDE_RUN]` | a run of single-byte instructions that slide — REX prefixes, the classic `0x41` "AAAA" |
| `[SLED_GEN]` | `rep stos*` with a 0x90-ish value loaded into the accumulator nearby |
| `[SLED_GEN_CALL]` | a memset-like constant followed by a call — noisy, needs `-G` |
| `[WX_SEGMENT]` / `[WX_SECTION]` | writable *and* executable |
| `[EXEC_STACK]` | `PT_GNU_STACK` with the execute bit |

Exit code 0 = nothing found, 1 = findings, 2 = error.

## Options

```
-t min_sled     minimum NOP run, default 32
-s min_slide    minimum single-byte slide run, 0 disables, default 64
-w gen_window   backward window for the generator heuristics, default 96
-a              scan the whole file raw when ELF region scanning does not apply
-G              extra noisy memset+call heuristic
-v              verbose
```

## Tests

```sh
make check      # 33 checks: byte encodings, planted sleds, false-positive ceiling
make fuzz       # malformed ELF under ASan + UBSan
make asan       # the suite under ASan + UBSan
make survey     # what the heuristics say about this machine's own binaries
```

`make check` has three parts that fail for different reasons: exact
instruction encodings asserted against hand-built byte files (no compiler
needed), real binaries with a planted sled or generator built at test time
with `gcc`, and a false-positive ceiling measured against the system's own
binaries so a new heuristic cannot quietly ruin the tool.

It scores 24 passed / 9 failed against the version before these fixes.

## Notes

`FIXES.md` records what was missed and why, including the `rep stosw`
encoding bug that made two of the generator patterns unreachable, and the
measurements behind the default thresholds.

Static analysis only: a sled generated at runtime cannot be seen in a file.
