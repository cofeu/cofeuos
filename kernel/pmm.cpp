#include "kernel.h"
#include "x86.h"
#include "pmm.h"

extern char __kernel_end;

static uint8_t* bits;          /* bit haritasi (bit=1 ayrilmis) */
static uint64_t base;          /* ilk yonetilen frame fiziksel adresi */
static uint64_t nframes;       /* yonetilen frame sayisi */
static uint64_t free_frames;   /* serbest kalan */
static uint64_t ram_top;       /* tespit edilen RAM ust siniri */
static uint64_t ram_kb;        /* toplam tespit edilen RAM (KB) */

/* CMOS NVRAM (RTC alanlari): port 0x70 = index, 0x71 = veri
   0x30/0x31 = 1MB..64MB boyut (KB), 0x17 = 64MB+ boyut (64KB birim) */
static uint8_t cmos_read(uint8_t reg) {
    outb(0x70, reg);
    io_wait();
    return inb(0x71);
}

/* boot sektorunun BIOS E820 (INT 15h) ile topladigi bellek haritasi */
struct E820Entry {
    uint64_t base, len;
    uint32_t type;      /* 1 = kullanilabilir */
    uint32_t pad;
};

constexpr uint64_t E820_BUF = 0x8000;
constexpr uint64_t E820_CNT = 0x7FF0;
constexpr uint64_t ONE_GIB  = 0x40000000ull;
constexpr uint64_t ONE_MIB  = 0x100000ull;

static void range_mark(uint64_t p, uint32_t n, bool used) {
    while (n--) {
        uint64_t idx = (p - base) >> 12;
        uint32_t byte = idx >> 3, bit = idx & 7;
        if (used) bits[byte] |= (uint8_t)(1u << bit);
        else      bits[byte] &= (uint8_t)~(1u << bit);
        p += 4096;
    }
}

extern "C" void pmm_init(void) {
    /* birincil: BIOS E820.  Tosbik: CMOS. */
    uint32_t cnt = *(const uint32_t*)E820_CNT;
    if (cnt > 64) cnt = 64;
    const E820Entry* map = (const E820Entry*)E820_BUF;

    ram_kb = 0;
    ram_top = 0;
    bool have_map = false;

    if (cnt) {
        kprintf("e820: %u kayit okundu\n", cnt);
        kslog("e820 count=%u\n", cnt);
        for (uint32_t i = 0; i < cnt; i++) {
            uint64_t b = map[i].base, l = map[i].len;
            if (map[i].type != 1) continue;
            have_map = true;
            ram_kb += l / 1024u;
            if (b < ONE_MIB) continue;              /* 1MB uzeri, 1GB alti olani isle */
            if (b >= ONE_GIB) continue;
            uint64_t end = b + l;
            if (end > ONE_GIB) end = ONE_GIB;
            if (end > ram_top) ram_top = end;
        }
        if (ram_kb > ONE_GIB / 1024u) ram_kb = ONE_GIB / 1024u;
        kslog("e820 usable_kb=%lu\n", ram_kb);
    }

    if (!have_map) {
        /* CMOS yedek yol (E820 yayinlamayan eski BIOS icin) */
        uint16_t ext_low = (uint16_t)((cmos_read(0x31) << 8) | cmos_read(0x30));
        uint8_t  ext_hi  = cmos_read(0x17); /* 64KB birim, 64MB ustu */
        uint64_t ext_kb  = ext_low + (uint64_t)ext_hi * 64u;
        kslog("cmos fallback ext=%luKB\n", ext_kb);
        ram_top = ONE_MIB + ext_kb * 1024u;
        ram_kb  = 1024u + ext_kb;
        if (ram_top > ONE_GIB) ram_top = ONE_GIB;
        if (ram_kb  > ONE_GIB / 1024u) ram_kb = ONE_GIB / 1024u;
    }

    /* cekirdek sonundan itibaren frame'lere gec */
    uint64_t start = (uint64_t)&__kernel_end;
    start = (start + 0xfffu) & ~0xfffu;
    if (start >= ram_top) { nframes = 0; base = 0; return; }

    base    = start;
    nframes = (ram_top - start) / 4096u;

    /* bit haritasini bolgenin basina yerlestir; o frame'ler yonetilmez */
    uint32_t bm_frames = (uint32_t)(((nframes + 7) / 8u + 4095u) / 4096u);
    bits = (uint8_t*)base;
    base += (uint64_t)bm_frames * 4096u;
    nframes -= bm_frames;
    memset(bits, 0, (nframes + 7) / 8u);               /* hepsi serbest */
    free_frames = nframes;
}

uint64_t pmm_alloc_frame(void) {
    for (uint64_t i = 0; i < nframes; i++) {
        uint32_t byte = i >> 3, bit = i & 7;
        if (!(bits[byte] & (uint8_t)(1u << bit))) {
            bits[byte] |= (uint8_t)(1u << bit);
            free_frames--;
            return base + (i << 12);
        }
    }
    return 0;
}

uint64_t pmm_alloc_range(uint32_t n) {
    if (!n) return 0;
    uint64_t run = 0;
    for (uint64_t i = 0; i <= nframes; i++) {
        if (i < nframes) {
            uint32_t byte = i >> 3, bit = i & 7;
            if (!(bits[byte] & (uint8_t)(1u << bit))) { run++; continue; }
        }
        if (run >= n) {
            uint64_t p = base + ((i - run) << 12);
            range_mark(p, n, true);
            free_frames -= n;
            return p;
        }
        run = 0;
    }
    return 0;
}

void pmm_free_frame(uint64_t phys) {
    if (phys < base || phys >= base + nframes * 4096u) return;
    range_mark(phys, 1, false);
    free_frames++;
}

void pmm_free_range(uint64_t phys, uint32_t n) {
    if (!n) return;
    if (phys < base || phys + (uint64_t)n * 4096u > base + nframes * 4096u) return;
    range_mark(phys, n, false);
    free_frames += n;
}

uint64_t pmm_total_kb(void)   { return ram_kb; }
uint64_t pmm_managed_kb(void) { return nframes * 4u; }
uint32_t pmm_free_frames(void){ return (uint32_t)free_frames; }
uint32_t pmm_total_frames(void){ return (uint32_t)nframes; }