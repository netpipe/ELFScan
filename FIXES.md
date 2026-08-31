# ELFScan — audit, fixes, and what is now tested

The starting point built clean under `-Wall -Wextra`, caught a real 200-byte
`0x90` sled and a `rep stosb` generator, stayed quiet on a clean binary, and
survived 4,500 malformed ELF files under AddressSanitizer without a single
crash or out-of-bounds read. `range_ok()` is written overflow-safe, which is
the thing that usually goes wrong in an ELF parser. The structure was sound.

What it could not see was the problem. Three detection gaps, each
demonstrated with a binary rather than argued from the source.

```
make          build
make check    33 checks: byte encodings, planted sleds, false-positive ceiling
make fuzz     malformed ELF under ASan + UBSan
make asan     the test suite under ASan + UBSan
make survey   what the heuristics say about this machine's own binaries
```

The suite scores **24 passed, 9 failed** against the original binary and
**33 passed, 0 failed** against this one. Every one of those 9 is a real
gap, not a renamed flag.

---

## 1. `rep stosw` is `66 F3 AB`, not `F3 66 AB`

`scan_generators` matched fixed byte strings and assumed the `F3` came
first:

```c
} else if (i + 3 <= len && buf[i + 1] == 0x66 && buf[i + 2] == 0xAB) {
    what = "rep stosw";
    klass = 3;
```

The assembler emits the prefixes the other way round:

```
$ printf '.text\nrep stosb\nrep stosw\nrep stosl\nrep stosq\n' | as -o e.o - && objdump -d e.o
   0:  f3 aa           rep stos %al,%es:(%rdi)
   2:  66 f3 ab        rep stos %ax,%es:(%rdi)
   5:  f3 ab           rep stos %eax,%es:(%rdi)
   7:  f3 48 ab        rep stos %rax,%es:(%rdi)
```

So `klass == 3` never fired, and `pat_ax_90` and `pat_ax_9090` — the two
patterns written specifically for the 16-bit case — had no reachable
caller. A binary built with `mov ax,0x9090; rep stosw` reported
`findings=0`.

Prefixes are legal in any order, so the fix is to stop matching strings:
collect `F3`, `66` and any REX first, then look at the opcode, and let
REX.W and the operand-size prefix decide which of stosd/stosw/stosq it
is. All four forms are now in the test suite with the encodings the
assembler actually produces.

*(This is the same shape as the `parse_comparison` bug in miniPython —
code that was written, was correct, and was never reached. `grep -c` for
callers is a ten-second audit.)*

## 2. Prefixed NOPs were invisible, and they are the common ones

`match_nop` listed nine encodings as literal byte strings. Real
toolchains pad with CS-prefixed forms that were not on the list:

| bytes | occurrences in /usr/bin/python3 |
|---|---|
| `66 66 2e 0f 1f 84 00 00 00 00 00` | 1445 |
| `66 2e 0f 1f 84 00 00 00 00 00` | 649 |

The failure mode is worse than a simple miss. Given a 440-byte block of
them, `match_nop` matched the `0f 1f 84 00 00 00 00 00` in the middle of
each instruction and the `66 66 2e` in front broke the run — so at
`-t 8` it reported **41 separate 8-byte runs**, and at the default
threshold of 32 it reported **nothing at all**. A contiguous 440-byte NOP
region read as forty small ones.

`match_nop` now counts prefixes first (`66`, the segment overrides
`2e 3e 26 36 64 65`, and at most one REX, which must come last) and then
decodes `0f 1f /0` properly through its ModRM, SIB and displacement,
capped at the 15-byte instruction limit. The same block is now one
finding of `len=440 insns=40`.

One subtlety the tests pin down: `48 90` is `nop`, but `41 90` is
`REX.B + 90` = `xchg r8d,eax`, a real instruction. `90` only counts when
REX.B is clear.

## 3. A sled does not have to be made of NOPs

Only the `0x90` family counted. A 300-byte run of `0x41` — "AAAA" in a
string, and in 64-bit mode a REX prefix, so *every byte of it is a valid
landing point* — was completely invisible. `findings=0`.

New finding type, `[SLIDE_RUN]`: a run of single-byte instructions that
each leave the machine usable. `0x90`, REX `0x40-0x4F`, `0x97`, `0x98`,
`0x99`, `0xF8`, `0xF9`, `0xFC`, plus the BCD adjusts `27 2F 37 3F` **only
for a 32-bit object**, because those are invalid opcodes in long mode and
cannot slide there. The ELF class is threaded down per file to decide.

It is reported separately from `[NOP_SLED]` on purpose: ASCII text and
padding inside an executable segment can look like this, so it needs its
own threshold rather than quietly widening the existing one. `-s N` sets
it, `-s 0` turns it off.

A run that decodes entirely as NOP instructions is skipped, because
`scan_nops` has already reported it. Checking the decode covers the run
exactly is better than checking for `0x90`, since `48 90` is a NOP whose
bytes are both in the slide set.

---

## Choosing the threshold by measuring, not by taste

Adding a heuristic to a scanner is easy; adding one that does not drown
the output is the part that needs evidence. Slide runs against 600 real
system binaries, with the NOP detector switched off so the number is
attributable:

| `-s` | binaries flagged by `[SLIDE_RUN]` |
|---|---|
| 16 | 2 |
| 24 | 1 |
| 32 | 1 |
| 48 | 0 |
| 64 | 0 |
| 96 | 0 |

The default is 64. Real sleds are hundreds of bytes, so the sensitivity
costs nothing, and the table is in the repo so the choice can be argued
with rather than trusted.

Overall false-positive rate across the same 600 binaries: **1.2% before,
1.3% after**. The prefix-aware matcher turned 1 NOP finding into 25 —
almost all of them long padding runs inside `/usr/bin/busybox`, which
were always there and were previously being fragmented — but only one
extra binary crossed into "flagged".

`tests/run.py` asserts the rate stays under 5%, so a future heuristic
cannot quietly ruin the tool. `make survey` prints the detail behind the
number.

---

## What was already right

Worth saying, because it is most of the file:

* Bounds checking. `range_ok(off, len, total)` is `off <= total && len <=
  total - off`, which does not overflow. Program and section header
  ranges are both checked before use, and a header entry whose range
  falls outside the file is skipped rather than trusted.
* 4,500 malformed ELFs — truncated, garbage headers, `e_phnum=65535`,
  `e_phoff=0xFFFFFFFFFFFFFFFF`, big-endian, unknown class, `e_phentsize=0`
  — across three option sets, under ASan and UBSan: zero crashes, hangs
  or out-of-bounds reads. Same again after these changes, plus a
  byte-boundary fuzz aimed at the new prefix and ModRM decoding, where a
  truncated instruction at the end of a region is exactly the thing that
  would read one byte too far.
* `PT_GNU_STACK` with `PF_X`, and `W+X` segments and sections, were
  already reported.

---

## Not done

* No disassembly. Run detection is byte-level, so a sled built from
  multi-byte instructions that each happen to be harmless will not be
  caught. That needs a length-decoder, which is a different project.
* `.rodata` living inside an `R+X` segment is scanned as code, because at
  the segment level there is nothing to tell them apart. Section-level
  scanning would be tighter but only relocatable objects reach that path
  today.
* Overlapping `PT_LOAD` segments would report the same bytes twice.
* Exit code 1 (findings) hides exit code 2 (errors) when a run has both.
  Worth knowing if you script it.