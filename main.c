/*
 * elfscan.c
 *
 * Single-file ELF scanner for defensive/educational use.
 *
 * Detects:
 *   - x86/x86-64 NOP sleds in executable ELF regions
 *   - runs of single-byte instructions that slide (REX prefixes, "AAAA")
 *   - Some possible NOP-sled generation routines using REP STOS*
 *   - W+X segments and executable stacks as risk markers
 *
 * Assumptions:
 *   - Little-endian ELF files.
 *   - x86/x86-64 NOP semantics.
 *   - Static analysis only; runtime generation cannot be fully detected statically.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o elfscan elfscan.c
 *
 * Usage:
 *   ./elfscan [-t min_sled] [-s min_slide] [-w gen_window] [-a] [-G] [-v] file...
 *
 * Exit codes:
 *   0 = no findings
 *   1 = findings detected
 *   2 = errors or bad usage
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#if defined(__has_include)
#  if __has_include(<elf.h>)
#include <elf.h>
#else
#define ELFSCAN_NEED_MINIMAL_ELF
#endif
#elif defined(__APPLE__)
#define ELFSCAN_NEED_MINIMAL_ELF
#else
#include <elf.h>
#endif

#ifdef ELFSCAN_NEED_MINIMAL_ELF

#include <stdint.h>

/*
 * Minimal ELF definitions needed by elfscan.c.
 * This is not a complete ELF header implementation.
 */

#define EI_NIDENT 16

#define ELFMAG  "\177ELF"
#define SELFMAG 4

#define EI_CLASS 4
#define ELFCLASS32 1
#define ELFCLASS64 2

#define EI_DATA 5
#define ELFDATA2LSB 1

#define EM_386 3
#define EM_X86_64 62

#define PT_LOAD 1
#define PT_GNU_STACK 0x6474e551

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define SHF_WRITE 1
#define SHF_EXECINSTR 4

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct {
    Elf64_Word sh_name;
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word sh_link;
    Elf64_Word sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

#endif /* ELFSCAN_NEED_MINIMAL_ELF */

#ifndef EM_X86_64
#define EM_X86_64 62
#endif

#ifndef EM_386
#define EM_386 3
#endif

#ifndef PT_GNU_STACK
#define PT_GNU_STACK 0x6474e551
#endif

#define DEFAULT_MIN_SLED 32
#define DEFAULT_GEN_WINDOW 96
#define DEFAULT_MIN_SEMANTIC 64

typedef struct {
    int min_sled;       /* minimum NOP run length in bytes */
    int min_semantic;   /* minimum single-byte-slide run length, 0 disables */
    int gen_window;     /* backward search window for generator heuristics */
    int scan_all;       /* scan raw file if no ELF executable regions found / non-ELF */
    int extra_gen;      /* enable noisier memset/call heuristic */
    int verbose;
    int is64;           /* set per file; decides which bytes can slide */
} Options;

static int range_ok(uint64_t off, uint64_t len, uint64_t total) {
    return off <= total && len <= total - off;
}

static size_t find_bytes(const uint8_t *hay, size_t haylen,
                         const uint8_t *needle, size_t needlelen) {
    if (needlelen == 0) return 0;
    if (haylen < needlelen) return SIZE_MAX;

    for (size_t i = 0; i + needlelen <= haylen; i++) {
        if (memcmp(hay + i, needle, needlelen) == 0) {
            return i;
        }
    }

    return SIZE_MAX;
}

/*
 * Match known x86/x86-64 NOP instructions.
 *
 * This intentionally focuses on common NOP forms used in sleds and
 * compiler padding. It is not a full x86 disassembler.
 *
 * Prefixes are counted first and separately.  Writing the encodings out
 * as fixed byte strings missed every prefixed form, and those are the
 * ones a compiler emits most: /usr/bin/python3 contains 1445 copies of
 * 66 66 2e 0f 1f 84 00 00 00 00 00.  A 440-byte block of them used to be
 * reported as forty separate eight-byte runs, because the 0f 1f 84 in the
 * middle matched and the 66 66 2e in front broke the run every time - so
 * the block never reached the sled threshold at all.
 *
 * Legal prefixes on a NOP:
 *   66       operand size, repeatable
 *   2e 3e 26 36 64 65   segment override (gas uses %cs = 2e for padding)
 *   40-4f    REX, at most one and it must be last
 * The instruction itself is 90, or 0f 1f /0 with a ModRM+SIB+disp.
 */
static int is_nop_prefix(uint8_t b) {
    return b == 0x66 || b == 0x2E || b == 0x3E ||
           b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65;
}

/* length of the 0f 1f form's ModRM + SIB + displacement, or 0 if not one */
static size_t nop_modrm_len(const uint8_t *p, size_t n) {
    if (n < 1) return 0;

    uint8_t modrm = p[0];
    uint8_t mod = (uint8_t)(modrm >> 6);
    uint8_t rm = (uint8_t)(modrm & 7);

    /* only /0 is the hint NOP */
    if (((modrm >> 3) & 7) != 0) return 0;

    size_t len = 1;

    if (mod != 3 && rm == 4) {          /* SIB byte follows */
        if (n < len + 1) return 0;
        len++;
    }

    if (mod == 1) {
        if (n < len + 1) return 0;
        len += 1;                        /* disp8 */
    } else if (mod == 2) {
        if (n < len + 4) return 0;
        len += 4;                        /* disp32 */
    } else if (mod == 0 && rm == 5) {
        if (n < len + 4) return 0;
        len += 4;                        /* rip-relative disp32 */
    }

    return len;
}

static size_t match_nop(const uint8_t *p, size_t n) {
    size_t i = 0;
    int rex = 0;      /* the REX byte itself, or 0 */

    /* an x86 instruction is at most 15 bytes including prefixes */
    while (i < n && i < 14) {
        if (is_nop_prefix(p[i])) {
            if (rex) break;              /* REX must be the last prefix */
            i++;
            continue;
        }

        if (p[i] >= 0x40 && p[i] <= 0x4F) {
            if (rex) break;
            rex = p[i];
            i++;
            continue;
        }

        break;
    }

    if (i >= n) return 0;

    /*
     * 90 is a NOP only while REX.B is clear: 48 90 is nop, but 41 90 is
     * REX.B + 90 = xchg r8d,eax, which is a real instruction.
     */
    if (p[i] == 0x90) {
        if (rex && (rex & 1)) return 0;
        return i + 1;
    }

    /* 0f 1f /0 - the multi-byte hint NOP */
    if (i + 1 < n && p[i] == 0x0F && p[i + 1] == 0x1F) {
        size_t m = nop_modrm_len(p + i + 2, n - i - 2);
        if (m == 0) return 0;

        size_t total = i + 2 + m;
        if (total > 15) return 0;
        return total;
    }

    return 0;
}

/*
 * A sled does not have to be built from NOPs.  Any single-byte
 * instruction that leaves the machine usable will slide, and the classic
 * one is 0x41 - "AAAA" in a string, and in 64-bit mode a REX prefix, so
 * every byte of the run is a valid landing point.  A 300-byte run of it
 * used to be completely invisible.
 *
 * These are reported separately from real NOP runs, because their false
 * positive profile is different: 0x00 padding and ASCII runs are
 * everywhere in a binary, so this needs its own threshold.
 */
static int semantic_nop_byte(uint8_t b, int is64) {
    if (b == 0x90) return 1;
    if (b >= 0x40 && b <= 0x4F) return 1;   /* REX in 64-bit, inc/dec in 32-bit */
    if (b == 0x97 || b == 0x98 || b == 0x99) return 1;
    if (b == 0xF8 || b == 0xF9 || b == 0xFC) return 1;

    /* daa/das/aaa/aas are invalid opcodes in long mode, so they cannot
       slide there - only count them for a 32-bit object */
    if (!is64 && (b == 0x27 || b == 0x2F || b == 0x37 || b == 0x3F)) return 1;

    return 0;
}

static const char *semantic_nop_name(uint8_t b) {
    if (b >= 0x40 && b <= 0x4F) return "REX prefix";
    if (b == 0x90) return "nop";
    if (b == 0x97) return "xchg eax,edi";
    if (b == 0x27 || b == 0x2F || b == 0x37 || b == 0x3F) return "bcd adjust (32-bit)";
    if (b == 0xF8 || b == 0xF9) return "clc/stc";
    if (b == 0xFC) return "cld";
    if (b == 0x98 || b == 0x99) return "cwde/cdq";
    return NULL;
}

static const char *severity_sled(size_t len) {
    if (len >= 256) return "high";
    if (len >= 64) return "medium";
    return "low";
}

static void scan_nops(const uint8_t *buf, size_t len,
                      uint64_t vbase, uint64_t fbase,
                      const char *region, const char *path,
                      const Options *opt, int *findings) {
    size_t i = 0;

    while (i < len) {
        size_t start = i;
        size_t run = 0;
        size_t insns = 0;

        while (i < len) {
            size_t l = match_nop(buf + i, len - i);
            if (!l) break;

            run += l;
            insns++;
            i += l;
        }

        if (run >= (size_t)opt->min_sled) {
            const char *sev = severity_sled(run);

            printf("[NOP_SLED] file=%s region=%s vaddr=0x%llx fileoff=0x%llx "
                   "len=%zu insns=%zu severity=%s\n",
                   path,
                   region,
                   (unsigned long long)(vbase + start),
                   (unsigned long long)(fbase + start),
                   run,
                   insns,
                   sev);

            (*findings)++;
        }

        if (run == 0) {
            i++;
        }
    }
}

/*
 * A run of single-byte instructions that all slide.  Reported separately
 * from real NOP runs because the false-positive profile is different -
 * ASCII text and padding inside an executable segment can look like this,
 * so it carries its own threshold.
 */
static void scan_semantic(const uint8_t *buf, size_t len,
                          uint64_t vbase, uint64_t fbase,
                          const char *region, const char *path,
                          const Options *opt, int *findings) {
    if (opt->min_semantic <= 0) return;

    size_t i = 0;

    while (i < len) {
        if (!semantic_nop_byte(buf[i], opt->is64)) {
            i++;
            continue;
        }

        size_t start = i;
        int seen[256];
        memset(seen, 0, sizeof(seen));

        while (i < len && semantic_nop_byte(buf[i], opt->is64)) {
            seen[buf[i]] = 1;
            i++;
        }

        size_t run = i - start;
        if (run < (size_t)opt->min_semantic) continue;

        /*
         * If the whole run decodes as NOP instructions then scan_nops has
         * already reported it and this would be a second finding for the
         * same bytes.  Checking that the decode covers the run exactly is
         * better than checking for 0x90, because 48 90 (rex.w nop) is a
         * NOP whose bytes are both in the slide set.
         */
        size_t k = start;
        while (k < i) {
            size_t l = match_nop(buf + k, i - k);
            if (!l) break;
            k += l;
        }
        if (k >= i) continue;

        int distinct = 0;
        uint8_t dominant = buf[start];
        size_t best = 0;

        for (int b = 0; b < 256; b++) {
            if (!seen[b]) continue;
            distinct++;

            size_t c = 0;
            for (size_t k = start; k < i; k++) if (buf[k] == (uint8_t)b) c++;
            if (c > best) { best = c; dominant = (uint8_t)b; }
        }

        const char *name = semantic_nop_name(dominant);

        printf("[SLIDE_RUN] file=%s region=%s vaddr=0x%llx fileoff=0x%llx "
               "len=%zu distinct=%d dominant=0x%02x (%s) severity=%s\n",
               path,
               region,
               (unsigned long long)(vbase + start),
               (unsigned long long)(fbase + start),
               run,
               distinct,
               (unsigned)dominant,
               name ? name : "?",
               severity_sled(run));

        (*findings)++;
    }
}

/*
 * Heuristic detector for possible NOP-sled generation routines.
 *
 * Looks for REP STOS forms:
 *   rep stosb  : F3 AA
 *   rep stosd  : F3 AB
 *   rep stosw  : F3 66 AB
 *   rep stosq  : F3 48 AB
 *
 * Then searches backward in a small window for accumulator loads containing
 * 0x90 or repeated 0x90 bytes.
 */
static void scan_generators(const uint8_t *buf, size_t len,
                            uint64_t vbase, uint64_t fbase,
                            const char *region, const char *path,
                            const Options *opt, int *findings) {
    static const uint8_t pat_al_90[] = {
        0xB0, 0x90
    };

    static const uint8_t pat_ax_90[] = {
        0x66, 0xB8, 0x90, 0x00
    };

    static const uint8_t pat_ax_9090[] = {
        0x66, 0xB8, 0x90, 0x90
    };

    static const uint8_t pat_eax_90[] = {
        0xB8, 0x90, 0x00, 0x00, 0x00
    };

    static const uint8_t pat_eax_90909090[] = {
        0xB8, 0x90, 0x90, 0x90, 0x90
    };

    static const uint8_t pat_rax_90_imm32[] = {
        0x48, 0xC7, 0xC0, 0x90, 0x00, 0x00, 0x00
    };

    static const uint8_t pat_rax_90_imm64[] = {
        0x48, 0xB8,
        0x90, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    static const uint8_t pat_rax_90x8[] = {
        0x48, 0xB8,
        0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90
    };

    size_t window = (size_t)opt->gen_window;

    for (size_t i = 0; i < len; ) {
        /*
         * Prefixes may appear in any order, and the assembler does not
         * use the order this code originally assumed: "rep stosw" is
         * 66 F3 AB, not F3 66 AB.  Matching fixed byte strings meant
         * klass 3 never fired, so pat_ax_90 and pat_ax_9090 were written
         * but never reached, and a mov ax,0x9090 + rep stosw generator
         * was reported as no findings at all.
         *
         * Collect the prefixes first instead, then look at the opcode.
         */
        if (buf[i] != 0xF3 && buf[i] != 0x66 && !(buf[i] >= 0x40 && buf[i] <= 0x4F)) {
            i++;
            continue;
        }

        size_t j = i;
        int have_rep = 0;
        int have_66 = 0;
        int rexw = 0;

        while (j < len && j - i < 4) {
            if (buf[j] == 0xF3) { have_rep = 1; j++; continue; }
            if (buf[j] == 0x66) { have_66 = 1; j++; continue; }
            if (buf[j] >= 0x40 && buf[j] <= 0x4F) {
                if (buf[j] & 0x08) rexw = 1;
                j++;
                continue;
            }
            break;
        }

        if (!have_rep || j >= len) {
            i++;
            continue;
        }

        const char *what = NULL;
        size_t ilen = 0;
        int klass = 0;

        if (buf[j] == 0xAA) {
            what = "rep stosb";
            ilen = j + 1 - i;
            klass = 1;
        } else if (buf[j] == 0xAB) {
            if (rexw) { what = "rep stosq"; klass = 4; }
            else if (have_66) { what = "rep stosw"; klass = 3; }
            else { what = "rep stosd"; klass = 2; }
            ilen = j + 1 - i;
        }

        if (!what) {
            i++;
            continue;
        }

        size_t wstart = (i > window) ? (i - window) : 0;
        size_t wlen = i - wstart;
        const uint8_t *wb = buf + wstart;

        int found = 0;
        const char *imm = NULL;

        if (klass == 1) {
            if (find_bytes(wb, wlen, pat_al_90, sizeof(pat_al_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov al,0x90";
            } else if (find_bytes(wb, wlen, pat_eax_90, sizeof(pat_eax_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90";
            } else if (find_bytes(wb, wlen, pat_rax_90_imm32, sizeof(pat_rax_90_imm32)) != SIZE_MAX) {
                found = 1;
                imm = "mov rax,0x90";
            } else if (find_bytes(wb, wlen, pat_rax_90_imm64, sizeof(pat_rax_90_imm64)) != SIZE_MAX) {
                found = 1;
                imm = "movabs rax,0x90";
            }
        } else if (klass == 2) {
            if (find_bytes(wb, wlen, pat_eax_90, sizeof(pat_eax_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90";
            } else if (find_bytes(wb, wlen, pat_eax_90909090, sizeof(pat_eax_90909090)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90909090";
            } else if (find_bytes(wb, wlen, pat_rax_90_imm32, sizeof(pat_rax_90_imm32)) != SIZE_MAX) {
                found = 1;
                imm = "mov rax,0x90";
            } else if (find_bytes(wb, wlen, pat_rax_90_imm64, sizeof(pat_rax_90_imm64)) != SIZE_MAX) {
                found = 1;
                imm = "movabs rax,0x90";
            }
        } else if (klass == 3) {
            if (find_bytes(wb, wlen, pat_ax_90, sizeof(pat_ax_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov ax,0x90";
            } else if (find_bytes(wb, wlen, pat_ax_9090, sizeof(pat_ax_9090)) != SIZE_MAX) {
                found = 1;
                imm = "mov ax,0x9090";
            } else if (find_bytes(wb, wlen, pat_eax_90, sizeof(pat_eax_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90";
            } else if (find_bytes(wb, wlen, pat_eax_90909090, sizeof(pat_eax_90909090)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90909090";
            }
        } else if (klass == 4) {
            if (find_bytes(wb, wlen, pat_rax_90_imm32, sizeof(pat_rax_90_imm32)) != SIZE_MAX) {
                found = 1;
                imm = "mov rax,0x90";
            } else if (find_bytes(wb, wlen, pat_rax_90_imm64, sizeof(pat_rax_90_imm64)) != SIZE_MAX) {
                found = 1;
                imm = "movabs rax,0x90";
            } else if (find_bytes(wb, wlen, pat_rax_90x8, sizeof(pat_rax_90x8)) != SIZE_MAX) {
                found = 1;
                imm = "movabs rax,0x9090909090909090";
            } else if (find_bytes(wb, wlen, pat_eax_90, sizeof(pat_eax_90)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90";
            } else if (find_bytes(wb, wlen, pat_eax_90909090, sizeof(pat_eax_90909090)) != SIZE_MAX) {
                found = 1;
                imm = "mov eax,0x90909090";
            }
        }

        if (found) {
            printf("[SLED_GEN] file=%s region=%s vaddr=0x%llx fileoff=0x%llx "
                   "%s near %s severity=medium\n",
                   path,
                   region,
                   (unsigned long long)(vbase + i),
                   (unsigned long long)(fbase + i),
                   what,
                   imm);

            (*findings)++;
        }

        i += ilen;
    }
}

/*
 * Optional noisy heuristic:
 *
 * Looks for memset-like constants being loaded into register arguments,
 * followed relatively soon by a CALL rel32 instruction.
 *
 * This can easily false positive, so it is disabled unless -G is used.
 */
static void scan_fill_calls(const uint8_t *buf, size_t len,
                            uint64_t vbase, uint64_t fbase,
                            const char *region, const char *path,
                            const Options *opt, int *findings) {
    static const uint8_t esi90[] = {
        0xBE, 0x90, 0x00, 0x00, 0x00
    };

    static const uint8_t esi9090[] = {
        0xBE, 0x90, 0x90, 0x90, 0x90
    };

    static const uint8_t rsi90[] = {
        0x48, 0xC7, 0xC6, 0x90, 0x00, 0x00, 0x00
    };

    struct fill_pat {
        const uint8_t *bytes;
        size_t len;
        const char *desc;
    };

    static const struct fill_pat pats[] = {
        { esi90,   sizeof(esi90),   "mov esi,0x90" },
        { esi9090, sizeof(esi9090), "mov esi,0x90909090" },
        { rsi90,   sizeof(rsi90),   "mov rsi,0x90" },
    };

    for (size_t i = 0; i < len; i++) {
        for (size_t k = 0; k < sizeof(pats) / sizeof(pats[0]); k++) {
            const struct fill_pat *p = &pats[k];

            if (p->len > len - i) {
                continue;
            }

            if (memcmp(buf + i, p->bytes, p->len) != 0) {
                continue;
            }

            size_t max = i + p->len + (size_t)opt->gen_window;
            if (max > len) max = len;

            for (size_t j = i + p->len; j + 5 <= max; j++) {
                if (buf[j] == 0xE8) {
                    printf("[SLED_GEN_CALL] file=%s region=%s vaddr=0x%llx "
                           "fileoff=0x%llx pattern=%s call_rel32 severity=low\n",
                           path,
                           region,
                           (unsigned long long)(vbase + i),
                           (unsigned long long)(fbase + i),
                           p->desc);

                    (*findings)++;

                    /* Skip past this pattern. */
                    i += p->len - 1;
                    break;
                }
            }

            /*
             * Whether or not we found a call, do not try other patterns
             * at this exact offset.
             */
            break;
        }
    }
}

static void scan_region(const uint8_t *data,
                        uint64_t fileoff, uint64_t len, uint64_t vaddr,
                        const char *region, const char *path,
                        const Options *opt, int *findings) {
    if (len == 0) return;

    if (fileoff > (uint64_t)SIZE_MAX || len > (uint64_t)SIZE_MAX) {
        return;
    }

    const uint8_t *buf = data + (size_t)fileoff;
    size_t sz = (size_t)len;

    if (opt->verbose) {
        printf("[INFO] file=%s scanning region=%s vaddr=0x%llx fileoff=0x%llx size=%llu\n",
               path,
               region,
               (unsigned long long)vaddr,
               (unsigned long long)fileoff,
               (unsigned long long)len);
    }

    scan_nops(buf, sz, vaddr, fileoff, region, path, opt, findings);
    scan_semantic(buf, sz, vaddr, fileoff, region, path, opt, findings);
    scan_generators(buf, sz, vaddr, fileoff, region, path, opt, findings);

    if (opt->extra_gen) {
        scan_fill_calls(buf, sz, vaddr, fileoff, region, path, opt, findings);
    }
}

static int scan_elf64(const uint8_t *data, size_t size,
                      const char *path, const Options *in_opt) {
    Options opt_store = *in_opt;
    opt_store.is64 = 1;
    const Options *opt = &opt_store;

    int findings = 0;
    int scanned = 0;

    if (size < sizeof(Elf64_Ehdr)) {
        printf("[SUMMARY] file=%s findings=0\n", path);
        return 0;
    }

    Elf64_Ehdr eh;
    memcpy(&eh, data, sizeof(eh));

    if (opt->verbose && eh.e_machine != EM_X86_64) {
        printf("[INFO] file=%s ELF64 machine=%u is not x86-64; NOP heuristics may not apply\n",
               path, (unsigned)eh.e_machine);
    }

    uint64_t fsize = (uint64_t)size;

    /*
     * Prefer program headers for executables/shared objects.
     */
    if (eh.e_phoff != 0 && eh.e_phnum != 0 &&
        eh.e_phentsize >= sizeof(Elf64_Phdr)) {

        uint64_t ph_total = (uint64_t)eh.e_phnum * eh.e_phentsize;

        if (range_ok(eh.e_phoff, ph_total, fsize)) {
            for (int i = 0; i < eh.e_phnum; i++) {
                uint64_t phoff = eh.e_phoff + (uint64_t)i * eh.e_phentsize;

                if (!range_ok(phoff, sizeof(Elf64_Phdr), fsize)) {
                    break;
                }

                Elf64_Phdr ph;
                memcpy(&ph, data + (size_t)phoff, sizeof(ph));

                if (ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X)) {
                    printf("[EXEC_STACK] file=%s phdr=%d severity=high\n",
                           path, i);
                    findings++;
                }

                if (ph.p_type != PT_LOAD) {
                    continue;
                }

                if ((ph.p_flags & PF_X) && (ph.p_flags & PF_W)) {
                    char perms[4] = {
                        (ph.p_flags & PF_R) ? 'R' : '-',
                        (ph.p_flags & PF_W) ? 'W' : '-',
                        (ph.p_flags & PF_X) ? 'X' : '-',
                        '\0'
                    };

                    printf("[WX_SEGMENT] file=%s phdr=%d perms=%s severity=high\n",
                           path, i, perms);
                    findings++;
                }

                if (!(ph.p_flags & PF_X) || ph.p_filesz == 0) {
                    continue;
                }

                if (!range_ok(ph.p_offset, ph.p_filesz, fsize)) {
                    if (opt->verbose) {
                        printf("[WARN] file=%s phdr=%d has invalid file range\n",
                               path, i);
                    }
                    continue;
                }

                char region[64];
                snprintf(region, sizeof(region), "PT_LOAD[%d]", i);

                scan_region(data, ph.p_offset, ph.p_filesz, ph.p_vaddr,
                            region, path, opt, &findings);

                scanned++;
            }
        }
    }

    /*
     * Fallback for relocatable objects or unusual binaries:
     * scan executable sections.
     */
    if (scanned == 0 &&
        eh.e_shoff != 0 && eh.e_shnum != 0 &&
        eh.e_shentsize >= sizeof(Elf64_Shdr)) {

        uint64_t sh_total = (uint64_t)eh.e_shnum * eh.e_shentsize;

        if (range_ok(eh.e_shoff, sh_total, fsize)) {
            for (int i = 0; i < eh.e_shnum; i++) {
                uint64_t shoff = eh.e_shoff + (uint64_t)i * eh.e_shentsize;

                if (!range_ok(shoff, sizeof(Elf64_Shdr), fsize)) {
                    break;
                }

                Elf64_Shdr sh;
                memcpy(&sh, data + (size_t)shoff, sizeof(sh));

                if (!(sh.sh_flags & SHF_EXECINSTR)) {
                    continue;
                }

                if ((sh.sh_flags & SHF_WRITE) && (sh.sh_flags & SHF_EXECINSTR)) {
                    printf("[WX_SECTION] file=%s section=%d severity=high\n",
                           path, i);
                    findings++;
                }

                if (sh.sh_size == 0) {
                    continue;
                }

                if (!range_ok(sh.sh_offset, sh.sh_size, fsize)) {
                    if (opt->verbose) {
                        printf("[WARN] file=%s section=%d has invalid file range\n",
                               path, i);
                    }
                    continue;
                }

                char region[64];
                snprintf(region, sizeof(region), "section[%d]", i);

                scan_region(data, sh.sh_offset, sh.sh_size, sh.sh_addr,
                            region, path, opt, &findings);

                scanned++;
            }
        }
    }

    if (scanned == 0 && opt->scan_all) {
        scan_region(data, 0, (uint64_t)size, 0, "RAW", path, opt, &findings);
        scanned++;
    }

    if (scanned == 0 && opt->verbose) {
        printf("[INFO] file=%s no executable ELF regions found\n", path);
    }

    printf("[SUMMARY] file=%s findings=%d\n", path, findings);
    return findings;
}

static int scan_elf32(const uint8_t *data, size_t size,
                      const char *path, const Options *in_opt) {
    Options opt_store = *in_opt;
    opt_store.is64 = 0;
    const Options *opt = &opt_store;

    int findings = 0;
    int scanned = 0;

    if (size < sizeof(Elf32_Ehdr)) {
        printf("[SUMMARY] file=%s findings=0\n", path);
        return 0;
    }

    Elf32_Ehdr eh;
    memcpy(&eh, data, sizeof(eh));

    if (opt->verbose && eh.e_machine != EM_386) {
        printf("[INFO] file=%s ELF32 machine=%u is not i386; NOP heuristics may not apply\n",
               path, (unsigned)eh.e_machine);
    }

    uint64_t fsize = (uint64_t)size;

    if (eh.e_phoff != 0 && eh.e_phnum != 0 &&
        eh.e_phentsize >= sizeof(Elf32_Phdr)) {

        uint64_t ph_total = (uint64_t)eh.e_phnum * eh.e_phentsize;

        if (range_ok(eh.e_phoff, ph_total, fsize)) {
            for (int i = 0; i < eh.e_phnum; i++) {
                uint64_t phoff = eh.e_phoff + (uint64_t)i * eh.e_phentsize;

                if (!range_ok(phoff, sizeof(Elf32_Phdr), fsize)) {
                    break;
                }

                Elf32_Phdr ph;
                memcpy(&ph, data + (size_t)phoff, sizeof(ph));

                if (ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X)) {
                    printf("[EXEC_STACK] file=%s phdr=%d severity=high\n",
                           path, i);
                    findings++;
                }

                if (ph.p_type != PT_LOAD) {
                    continue;
                }

                if ((ph.p_flags & PF_X) && (ph.p_flags & PF_W)) {
                    char perms[4] = {
                        (ph.p_flags & PF_R) ? 'R' : '-',
                        (ph.p_flags & PF_W) ? 'W' : '-',
                        (ph.p_flags & PF_X) ? 'X' : '-',
                        '\0'
                    };

                    printf("[WX_SEGMENT] file=%s phdr=%d perms=%s severity=high\n",
                           path, i, perms);
                    findings++;
                }

                if (!(ph.p_flags & PF_X) || ph.p_filesz == 0) {
                    continue;
                }

                if (!range_ok(ph.p_offset, ph.p_filesz, fsize)) {
                    if (opt->verbose) {
                        printf("[WARN] file=%s phdr=%d has invalid file range\n",
                               path, i);
                    }
                    continue;
                }

                char region[64];
                snprintf(region, sizeof(region), "PT_LOAD[%d]", i);

                scan_region(data, ph.p_offset, ph.p_filesz, ph.p_vaddr,
                            region, path, opt, &findings);

                scanned++;
            }
        }
    }

    if (scanned == 0 &&
        eh.e_shoff != 0 && eh.e_shnum != 0 &&
        eh.e_shentsize >= sizeof(Elf32_Shdr)) {

        uint64_t sh_total = (uint64_t)eh.e_shnum * eh.e_shentsize;

        if (range_ok(eh.e_shoff, sh_total, fsize)) {
            for (int i = 0; i < eh.e_shnum; i++) {
                uint64_t shoff = eh.e_shoff + (uint64_t)i * eh.e_shentsize;

                if (!range_ok(shoff, sizeof(Elf32_Shdr), fsize)) {
                    break;
                }

                Elf32_Shdr sh;
                memcpy(&sh, data + (size_t)shoff, sizeof(sh));

                if (!(sh.sh_flags & SHF_EXECINSTR)) {
                    continue;
                }

                if ((sh.sh_flags & SHF_WRITE) && (sh.sh_flags & SHF_EXECINSTR)) {
                    printf("[WX_SECTION] file=%s section=%d severity=high\n",
                           path, i);
                    findings++;
                }

                if (sh.sh_size == 0) {
                    continue;
                }

                if (!range_ok(sh.sh_offset, sh.sh_size, fsize)) {
                    if (opt->verbose) {
                        printf("[WARN] file=%s section=%d has invalid file range\n",
                               path, i);
                    }
                    continue;
                }

                char region[64];
                snprintf(region, sizeof(region), "section[%d]", i);

                scan_region(data, sh.sh_offset, sh.sh_size, sh.sh_addr,
                            region, path, opt, &findings);

                scanned++;
            }
        }
    }

    if (scanned == 0 && opt->scan_all) {
        scan_region(data, 0, (uint64_t)size, 0, "RAW", path, opt, &findings);
        scanned++;
    }

    if (scanned == 0 && opt->verbose) {
        printf("[INFO] file=%s no executable ELF regions found\n", path);
    }

    printf("[SUMMARY] file=%s findings=%d\n", path, findings);
    return findings;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-t min_sled] [-s min_slide] [-w gen_window] [-a] [-G] [-v] file...\n"
        "\n"
        "Options:\n"
        "  -t min_sled     Minimum NOP sled length in bytes, default %d\n"
        "  -s min_slide    Minimum single-byte slide run, 0 disables, default %d\n"
        "  -w gen_window   Backward search window for generator heuristics, default %d\n"
        "  -a              Scan whole file as raw if ELF region scanning does not apply\n"
        "  -G              Enable extra noisy memset/call sled-generation heuristic\n"
        "  -v              Verbose output\n"
        "  -h              Show this help\n"
        "\n"
        "Exit codes:\n"
        "  0 = no findings\n"
        "  1 = findings detected\n"
        "  2 = errors or bad usage\n",
        prog,
        DEFAULT_MIN_SLED,
        DEFAULT_MIN_SEMANTIC,
        DEFAULT_GEN_WINDOW);
}

static int scan_file(const char *path, const Options *opt) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[ERROR] file=%s open=%s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "[ERROR] file=%s fstat=%s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[ERROR] file=%s not a regular file\n", path);
        close(fd);
        return -1;
    }

    if (st.st_size <= 0) {
        fprintf(stderr, "[ERROR] file=%s empty file\n", path);
        close(fd);
        return -1;
    }

    size_t size = (size_t)st.st_size;

    const uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        fprintf(stderr, "[ERROR] file=%s mmap=%s\n", path, strerror(errno));
        return -1;
    }

    int findings = 0;

    if (size >= EI_NIDENT && memcmp(data, ELFMAG, SELFMAG) == 0) {
        if (data[EI_DATA] != ELFDATA2LSB) {
            fprintf(stderr,
                    "[WARN] file=%s unsupported ELF endianness; structural parsing disabled\n",
                    path);

            if (opt->scan_all) {
                scan_region(data, 0, (uint64_t)size, 0, "RAW", path, opt, &findings);
            }

            printf("[SUMMARY] file=%s findings=%d\n", path, findings);
        } else if (data[EI_CLASS] == ELFCLASS64) {
            findings = scan_elf64(data, size, path, opt);
        } else if (data[EI_CLASS] == ELFCLASS32) {
            findings = scan_elf32(data, size, path, opt);
        } else {
            fprintf(stderr, "[WARN] file=%s unknown ELF class\n", path);

            if (opt->scan_all) {
                scan_region(data, 0, (uint64_t)size, 0, "RAW", path, opt, &findings);
            }

            printf("[SUMMARY] file=%s findings=%d\n", path, findings);
        }
    } else if (opt->scan_all) {
        scan_region(data, 0, (uint64_t)size, 0, "RAW", path, opt, &findings);
        printf("[SUMMARY] file=%s findings=%d\n", path, findings);
    } else {
        fprintf(stderr, "[ERROR] file=%s not an ELF file\n", path);
        munmap((void *)data, size);
        return -1;
    }

    munmap((void *)data, size);
    return findings;
}

int main(int argc, char **argv) {
    Options opt;
    opt.min_sled = DEFAULT_MIN_SLED;
    opt.min_semantic = DEFAULT_MIN_SEMANTIC;
    opt.is64 = 1;
    opt.gen_window = DEFAULT_GEN_WINDOW;
    opt.scan_all = 0;
    opt.extra_gen = 0;
    opt.verbose = 0;

    int c;

    while ((c = getopt(argc, argv, "t:s:w:aGvh")) != -1) {
        switch (c) {
            case 't':
                opt.min_sled = atoi(optarg);
                if (opt.min_sled < 1) opt.min_sled = 1;
                break;

            case 's':
                opt.min_semantic = atoi(optarg);
                if (opt.min_semantic < 0) opt.min_semantic = 0;
                break;

            case 'w':
                opt.gen_window = atoi(optarg);
                if (opt.gen_window < 0) opt.gen_window = 0;
                break;

            case 'a':
                opt.scan_all = 1;
                break;

            case 'G':
                opt.extra_gen = 1;
                break;

            case 'v':
                opt.verbose = 1;
                break;

            case 'h':
                usage(argv[0]);
                return 0;

            default:
                usage(argv[0]);
                return 2;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 2;
    }

    int errors = 0;
    int detections = 0;

    for (; optind < argc; optind++) {
        int r = scan_file(argv[optind], &opt);

        if (r < 0) {
            errors++;
        } else if (r > 0) {
            detections++;
        }
    }

    if (detections > 0) {
        return 1;
    }

    if (errors > 0) {
        return 2;
    }

    return 0;
}