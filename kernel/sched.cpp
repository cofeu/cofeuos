#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "mmio.h"
#include "sched.h"
#include "net.h"

#define SCHED_DEBUG 0

namespace {

/* ---- proses tablosu ---- */
enum { P_EMPTY = 0, P_READY = 1, P_RUNNING = 2, P_SLEEPING = 3, P_ZOMBIE = 4 };

constexpr int      MAX_PROC    = 32;
constexpr uint16_t UCS         = 0x2B;   /* user kod 0x28 | RPL3 */
constexpr uint16_t UDS         = 0x23;   /* user veri 0x20 | RPL3 */
constexpr size_t   KSTACK_SIZE = 8192;

/* kullanici sanal adres duzeni: 2MB pencere @ 0x40000000 (4KB sayfalar).
   Kod paylasilan RO sayfalarda, yigincik prosese ozel RW sayfalarinda. */
constexpr uint64_t USER_IMG_BASE    = 0x40000000ull;
constexpr uint64_t USER_WINDOW_END  = 0x40020000ull;
constexpr uint64_t USER_STACK_TOP   = 0x4001F000ull;   /* pencere - 1 sayfa koruma */
constexpr int      USER_STACK_PAGES = 4;               /* 16KB */
constexpr int      USER_CODE_MAX_PAGES = 256;          /* 1MB max kod/veri bolgesi */

#ifndef USER_ENTRY_ADDR
#define USER_ENTRY_ADDR USER_IMG_BASE
#endif

/* isr_common'un 15 push'u sonrasi frame hizalanmasi (rsp r15'i isaret eder) */
enum {
    OFF_R15=0, OFF_R14, OFF_R13, OFF_R12, OFF_R11, OFF_R10, OFF_R9,
    OFF_R8, OFF_RDI, OFF_RSI, OFF_RBP, OFF_RBX, OFF_RDX, OFF_RCX, OFF_RAX,
    OFF_VEC, OFF_ERR, OFF_RIP, OFF_CS, OFF_RFLAGS, OFF_USRSP, OFF_SS
};

struct Process {
    uint16_t pid;
    char     name[15];
    uint8_t  state;
    uint64_t ctx;            /* kernel yigininda saklanan frame (isr sonrasi rsp) */
    uint64_t kstack;         /* kernel yigini (kmalloc, supervisor) */
    uint64_t cr3;            /* prosese ozel PML4 (fiziksel) */
    uint64_t pml4, pdpt, pd, pt;            /* adres alani tablolari */
    uint64_t stk_pages[USER_STACK_PAGES];   /* kullanici yigini fiziksel sayfalari */
    int      user_code_pages;               /* 0: paylasilan gomulu imaj; >0: ozel */
    uint64_t code_frames[USER_CODE_MAX_PAGES];
    uint64_t waketick;
    uint64_t preempts;
    uint32_t exitcode;
    uint64_t start_tick;        /* baslangic tick'i (calisma suresi hesabi) */
};

Process     table[MAX_PROC];
Process*    cur = NULL;
int         cur_idx = -1;
uint64_t    kernel_ctx = 0;
bool        kernel_ctx_valid = false;
bool        sched_ready = false;   /* spawn cagrilari bitince kullaniciya gecilir */

/* ---- gomulu kullanici imaji: paylasilan RO sayfalar ---- */
extern "C" char _binary_user_user_demo_bin_start[];
extern "C" char _binary_user_user_demo_bin_end[];
uint64_t img_frames[128];
int      img_pages = 0;

/* ---- PID ------------
   karisik stil: Linux gibi artan / en kucuk ozgur, BSD gibi wrap sonrasi
   yeniden kullanim, Windows gibi 4 haneli hex ekranda goruntulenir (ps). */

int pid_alloc(void) {
    for (uint32_t p = 1; p <= 0xFFFFu; p++) {
        bool used = false;
        for (int i = 0; i < MAX_PROC; i++)
            if (table[i].state != P_EMPTY && table[i].pid == p) { used = true; break; }
        if (!used) return (int)p;
    }
    return -1;
}

int find_by_pid(uint16_t pid) {
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state != P_EMPTY && table[i].pid == pid) return i;
    return -1;
}

void vm_free(Process& p);

int find_hole(void) {
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state == P_EMPTY) return i;
    /* zombi slotlari da geri kazan */
    for (int i = 0; i < MAX_PROC; i++) {
        if (table[i].state != P_ZOMBIE) continue;
        Process& p = table[i];
        vm_free(p);
        if (p.kstack) kfree((void*)p.kstack);
        p.pid = 0; p.state = P_EMPTY;
        return i;
    }
    return -1;
}

void wake_sleepers(void) {
    uint64_t now = timer_get_ticks();
    for (int i = 0; i < MAX_PROC; i++) {
        Process& p = table[i];
        if (p.state == P_SLEEPING && now >= p.waketick) p.state = P_READY;
    }
}

/* siralama: cur'dan sonra basla, gerekiyorsa cur'a (ready ise) dus - round robin */
Process* pick_ready(const Process* skip) {
    for (int k = 1; k <= MAX_PROC; k++) {
        int idx = (cur_idx + k) % MAX_PROC;
        Process* p = &table[idx];
        if (p->state != P_READY) continue;
        if (p == skip) continue;
        return p;
    }
    if (skip && skip->state == P_READY) return const_cast<Process*>(skip);
    return NULL;
}

/* ---- adres alani yonetimi ---- */
uint64_t alloc_zero_frame(void) {
    uint64_t f = pmm_alloc_frame();
    if (f) memset((void*)f, 0, 4096);
    return f;
}

bool uaddr_ok(uint64_t a, uint64_t n) {
    return a >= USER_IMG_BASE && n <= USER_WINDOW_END - USER_IMG_BASE &&
           a + n <= USER_WINDOW_END;
}

/* kullanici penceresinden NUL sonlu yolu (max 95 bayt) kernel tamponuna kopyalar. */
bool copy_user_path(uint64_t src, char* out, int maxlen) {
    if (!uaddr_ok(src, maxlen)) return false;
    const char* s = (const char*)src;
    for (int i = 0; i < maxlen; i++) {
        if (s[i] == 0) { out[i] = 0; return true; }
        out[i] = s[i];
    }
    return false;                         /* sonlandirilmamis */
}

/* Engelleyici ag syscall'lari icin sinirli sti penceresi: gercek IRQ'lar
   (timer -> nic_poll_all + net_tcp_poll_all) beklerken calisir; ctx henuz
   sched'e verilmedigi icin bayrak geri alinir ve syscall devam eder. */
static uint64_t rflags_get(void) {
    uint64_t fl; asm volatile("pushfq; pop %0" : "=r"(fl)); return fl;
}
static void rflags_set(uint64_t fl) {
    asm volatile("push %0; popfq" :: "r"(fl) : "cc", "memory");
}
struct IntrLatch {
    uint64_t fl;
    IntrLatch() : fl(rflags_get()) { asm volatile("sti"); }
    ~IntrLatch() { rflags_set(fl); }
};

/* gomulu kullanici imajini bir kez PMM'e kopyala; tum prosesler paylasir */
void load_image(void) {
    uint64_t start = (uint64_t)_binary_user_user_demo_bin_start;
    uint64_t end   = (uint64_t)_binary_user_user_demo_bin_end;
    uint64_t sz    = end - start;
    if (!sz || sz > 128 * 4096ull) { img_pages = 0; return; }
    img_pages = (int)((sz + 4095) / 4096);
    uint64_t base = pmm_alloc_range((uint32_t)img_pages);
    if (!base) { img_pages = 0; return; }
    for (int i = 0; i < img_pages; i++) img_frames[i] = base + (uint64_t)i * 4096;
    memcpy((void*)base, _binary_user_user_demo_bin_start, (size_t)sz);
}

/* Yeni adres alani: kernel kimlik 0..1GB (supervisor) + 2MB kullanici penceresi.
   f-cevreler: pml4[0]->pdpt; pdpt[0]=kernel PD (supervisor); pdpt[1]->pd;
               pd[0]->pt; pt[] = imaj (RO paylasilan) + yigincik (RW ozel).
   code_frames: yuklenecek kod sayfalari (fiziksel, pte'ye RW yazilir);
   n_pages: kod sayfasi sayisi. NULL ise paylasilan gomulu imaj sayfalari. */
void vm_build(Process& p, const uint64_t* code_frames, int n_pages) {
    p.pml4 = alloc_zero_frame();
    p.pdpt = alloc_zero_frame();
    p.pd   = alloc_zero_frame();
    p.pt   = alloc_zero_frame();
    if (!p.pml4 || !p.pdpt || !p.pd || !p.pt) { vm_free(p); return; }

    volatile uint64_t* pml4p = (volatile uint64_t*)p.pml4;
    volatile uint64_t* pdptp = (volatile uint64_t*)p.pdpt;
    volatile uint64_t* pdp   = (volatile uint64_t*)p.pd;
    volatile uint64_t* pte   = (volatile uint64_t*)p.pt;

    pml4p[0] = p.pdpt | 0x7;              /* P|RW|U */
    pdptp[0] = 0x72000 | 0x3;             /* ortak kernel PD (0..1GB), supervisor */
    pdptp[1] = p.pd | 0x7;                /* 0x40000000-0x80000000 penceresi */
    if (mmio_shared_pd()) pdptp[3] = mmio_shared_pd() | 0x3;  /* 0xC0000000+ MMIO kimligi */
    pdp[0]   = p.pt | 0x7;

    p.user_code_pages = n_pages;
    if (code_frames) {
        for (int i = 0; i < n_pages && i < USER_CODE_MAX_PAGES; i++) {
            p.code_frames[i] = code_frames[i];
            pte[i] = code_frames[i] | 0x5;     /* P|U, salt-okunur kod */
        }
    } else {
        for (int i = 0; i < img_pages; i++)
            pte[i] = img_frames[i] | 0x5;     /* P|U, salt-okunur (paylasilan) */
    }

    for (int k = 0; k < USER_STACK_PAGES; k++) {
        uint64_t f = alloc_zero_frame();
        if (!f) break;
        p.stk_pages[k] = f;
        int idx = (int)(((USER_STACK_TOP >> 12) - 1 - k) & 0x1FFu);  /* PT index */
        pte[idx] = f | 0x7;                                /* P|RW|U */
    }
    p.cr3 = p.pml4;
}

void vm_new(Process& p) { vm_build(p, NULL, 0); }

void vm_free(Process& p) {
    if (p.user_code_pages > 0)                      /* prosese ozel kod sayfalari */
        for (int i = 0; i < p.user_code_pages; i++)
            if (p.code_frames[i]) { pmm_free_frame(p.code_frames[i]); p.code_frames[i] = 0; }
    for (int k = 0; k < USER_STACK_PAGES; k++)
        if (p.stk_pages[k]) { pmm_free_frame(p.stk_pages[k]); p.stk_pages[k] = 0; }
    if (p.pt)   { pmm_free_frame(p.pt);   p.pt = 0; }
    if (p.pd)   { pmm_free_frame(p.pd);   p.pd = 0; }
    if (p.pdpt) { pmm_free_frame(p.pdpt); p.pdpt = 0; }
    if (p.pml4) { pmm_free_frame(p.pml4); p.pml4 = 0; }
    p.cr3 = 0;
}

/* isr_common'un erteledigi frame: r15 push'tan iretq frame'ine kadar */
uint64_t build_initial_context2(Process& p, uint64_t entry) {
    uint64_t* sp = (uint64_t*)(p.kstack + KSTACK_SIZE);
    *--sp = UDS;                        /* [21] ss        */
    *--sp = USER_STACK_TOP;             /* [20] usr rsp    */
    *--sp = 0x202;                      /* [19] rflags IF  */
    *--sp = UCS;                        /* [18] cs         */
    *--sp = entry;                      /* [17] rip */
    *--sp = 0;                          /* [16] err        */
    *--sp = 0;                          /* [15] vec        */
    for (int i = 14; i >= 0; i--) *--sp = 0;   /* [14..0] regler */
    return (uint64_t)sp;
}

uint64_t build_initial_context(Process& p) {
    return build_initial_context2(p, USER_ENTRY_ADDR);
}

/* fork icin: ana surecin syscall anindaki register'ini kopyala, rax=0 (cocuk) */
uint64_t build_fork_context(Process& c, const uint64_t* pr) {
    uint64_t* sp = (uint64_t*)(c.kstack + KSTACK_SIZE);
    *--sp = pr[OFF_SS];             /* [21] */
    *--sp = pr[OFF_USRSP];          /* [20] */
    *--sp = pr[OFF_RFLAGS];         /* [19] */
    *--sp = pr[OFF_CS];             /* [18] */
    *--sp = pr[OFF_RIP];            /* [17] */
    *--sp = 0;                      /* [16] err */
    *--sp = 0;                      /* [15] vec */
    for (int i = 14; i >= 0; i--)
        *--sp = (i == OFF_RAX) ? 0 : pr[i];
    return (uint64_t)sp;
}

} /* namespace */

extern "C" void sched_init(void) {
    for (int i = 0; i < MAX_PROC; i++) {
        table[i].state = P_EMPTY;
        table[i].pid   = 0;
        table[i].cr3   = 0;
    }
    cur = NULL; cur_idx = -1;
    kernel_ctx = 0; kernel_ctx_valid = false;
    sched_ready = false;
    load_image();
}

extern "C" void sched_go(void) { sched_ready = true; }

extern "C" int sched_spawn(const char* name) {
    int i = find_hole();
    if (i < 0) return -1;

    void* k = kmalloc(KSTACK_SIZE);
    if (!k) return -1;

    int pid = pid_alloc();
    if (pid < 0) { kfree(k); return -1; }

    Process& p = table[i];
    memset(&p, 0, sizeof(p));
    p.pid      = (uint16_t)pid;
    p.state    = P_EMPTY;               /* kurulum bitene kadar secilemez */
    p.kstack   = (uint64_t)k;

    int nl = (int)strlen(name);
    if (nl > 14) nl = 14;
    memcpy(p.name, name, (size_t)nl);
    p.name[nl] = 0;

    vm_new(p);
    if (!p.cr3) { kfree(k); p.state = P_EMPTY; p.pid = 0; return -1; }

    p.start_tick = timer_get_ticks();
    p.ctx = build_initial_context(p);
    p.state = P_READY;                   /* adres alani + ctx hazir olunca */
    return (int)p.pid;
}

/* ---- gercek ELF exec: /sys bizim .cexe dosyalarini diskten okur,
   segment'leri bellege kopyalar ve e_entry'den baslatir. ---- */

/* ELF64 header/program-header sabitleri (extern header kutuphanesi yok) */
#define ELF_MAGIC_B0 0x7F
#define ELF_MAGIC_B1 'E'
#define ELF_MAGIC_B2 'L'
#define ELF_MAGIC_B3 'F'

#define PT_LOAD    1

struct __attribute__((packed)) Elf64_EhdrL {
    uint8_t  ident[16];     /* 0  */
    uint16_t type;          /* 16 */
    uint16_t machine;       /* 18 */
    uint32_t version;       /* 20 */
    uint64_t entry;         /* 24 */
    uint64_t phoff;         /* 32 */
    uint64_t shoff;         /* 40 */
    uint32_t flags;         /* 48 */
    uint16_t ehsize;        /* 52 */
    uint16_t phentsize;     /* 54 */
    uint16_t phnum;         /* 56 */
    uint16_t shstrndx;      /* 58 */
};
static_assert(sizeof(Elf64_EhdrL) == 60, "ehdr layout");

struct __attribute__((packed)) Elf64_PhdrL {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};
static_assert(sizeof(Elf64_PhdrL) == 56, "phdr layout");

static bool elf_is_valid(const Elf64_EhdrL* eh) {
    return eh->ident[0] == ELF_MAGIC_B0 && eh->ident[1] == ELF_MAGIC_B1 &&
           eh->ident[2] == ELF_MAGIC_B2 && eh->ident[3] == ELF_MAGIC_B3;
}

static uint8_t elf_buf[16384];
static uint32_t elf_len = 0;
static uint64_t elf_entry = 0;

/* ELF icinde cofeu cexe imza notunu (.note.cofeu) ara.
   ELF note kafasi + govde: namesz=8, descsz=8, type=0xC0FE,
   name="COFEUOS\0", desc="COFEU..."  -- tumu bayt dizisi olarak. */
static bool elf_has_cofeu_note(void) {
    if (elf_len < 24) return false;
    for (uint32_t off = 0; off + 24 <= elf_len; off++) {
        const uint8_t* p = elf_buf + off;
        if (p[0] == 8  && p[1] == 0 && p[2] == 0 && p[3] == 0 &&
            p[4] == 8  && p[5] == 0 && p[6] == 0 && p[7] == 0 &&
            p[8] == 0xFE && p[9] == 0xC0 && p[10] == 0 && p[11] == 0 &&
            p[12] == 'C' && p[13] == 'O' && p[14] == 'F' && p[15] == 'E' &&
            p[16] == 'U' && p[17] == 'O' && p[18] == 'S' && p[19] == 0 &&
            p[20] == 'C' && p[21] == 'O' && p[22] == 'F' && p[23] == 'E')
            return true;
    }
    return false;
}

/* ELF'i dogrula; PT_LOAD segment'lerine prosese ozel fiziksel sayfalar ayirip
   iceriklerini kopyalar. code_frames[u]: fiziksel adres; user_code_pages:
   ayrilan sayfa sayisi (son segment'in son sayfasi). Basarisizsa 0 doner ve
   ayrilmis sayfalari birakir (cagiran vm_free ile temizler). */
static bool elf_parse_and_load(uint64_t* code_frames, int* user_code_pages) {
    Elf64_EhdrL* eh = (Elf64_EhdrL*)elf_buf;
    if (elf_len < sizeof(Elf64_EhdrL)) return false;
    if (!elf_is_valid(eh)) return false;
    if (eh->phentsize < sizeof(Elf64_PhdrL) || !eh->phnum) return false;
    elf_entry = eh->entry;

    const uint8_t* phbase = elf_buf + eh->phoff;
    int highest_vp = -1;

    for (uint16_t pi = 0; pi < eh->phnum; pi++) {
        const uint8_t* ph = phbase + (size_t)pi * eh->phentsize;
        Elf64_PhdrL pr;
        memcpy(&pr, ph, sizeof(pr));
        if (pr.type != PT_LOAD) continue;
        if (pr.memsz == 0) continue;

        uint64_t va = pr.vaddr;
        /* kullanici penceresini hic kapsamayan segmentleri atla (ornek:
           not LOAD'u 0x400000'da, bizim 0x40000000 penceremizin disinda) */
        if (va + pr.memsz <= USER_IMG_BASE || va >= USER_WINDOW_END) continue;
        if (va < USER_IMG_BASE || va + pr.memsz > USER_WINDOW_END) return false;

        uint32_t vp_end = (uint32_t)(((va + pr.memsz - 1ull - USER_IMG_BASE) >> 12) + 1);
        if (vp_end > (uint32_t)USER_CODE_MAX_PAGES) return false;
        if ((int)vp_end > highest_vp) highest_vp = (int)vp_end;
    }
    if (highest_vp < 0) return false;

    /* sayfalari ayir */
    for (int i = 0; i <= highest_vp; i++) {
        uint64_t f = alloc_zero_frame();
        if (!f) { *user_code_pages = i; return false; }
        code_frames[i] = f;
    }
    *user_code_pages = highest_vp + 1;

    /* segment iceriklerini kopyala */
    for (uint16_t pi = 0; pi < eh->phnum; pi++) {
        const uint8_t* ph = phbase + (size_t)pi * eh->phentsize;
        Elf64_PhdrL pr;
        memcpy(&pr, ph, sizeof(pr));
        if (pr.type != PT_LOAD || pr.memsz == 0) continue;

        uint64_t va     = pr.vaddr;
        if (va + pr.memsz <= USER_IMG_BASE || va >= USER_WINDOW_END) continue;
        uint64_t voff0  = va - USER_IMG_BASE;   /* va >= USER_IMG_BASE oldugundan guvenli */
        uint64_t src    = pr.offset;
        uint64_t filesz = pr.filesz;
        uint64_t memsz  = pr.memsz;
        uint32_t vp_start = (uint32_t)(voff0 >> 12);
        uint32_t vp_end   = (uint32_t)(((voff0 + memsz - 1) >> 12) + 1);

        for (uint32_t vp = vp_start; vp < vp_end; vp++) {
            uint8_t* page = (uint8_t*)code_frames[vp];
            memset(page, 0, 4096);
            uint64_t page_voff = (uint64_t)vp * 4096ull;
            for (uint64_t off = 0; off < 4096; off++) {
                uint64_t abs_off = (page_voff + off) - voff0;
                if (abs_off >= memsz) break;
                if (abs_off < filesz) {
                    uint64_t file_off = src + abs_off;
                    if (file_off < elf_len)
                        page[off] = elf_buf[file_off];
                }
            }
        }
    }
    return true;
}

extern "C" int sched_exec_file(const char* path) {
    if (!sched_ready && cur) { kslog("exec: kernel modda\n"); return -1; }

    elf_len = 0;
    if (!fs::read_file(0, path, elf_buf, sizeof(elf_buf), &elf_len)) {
        kslog("exec: dosya okunamadi: %s\n", path);
        return -1;
    }
    if (elf_len < sizeof(Elf64_EhdrL)) {
        kslog("exec: elf cok kucuk (%u): %s\n", elf_len, path);
        return -1;
    }

    /* kac sayfa lazim oldugunu bellekte bul, ayir */
    Elf64_EhdrL* eh = (Elf64_EhdrL*)elf_buf;
    if (!elf_is_valid(eh)) {
        kslog("exec: elf magically gecersiz: %s\n", path);
        return -1;
    }
    if (!elf_has_cofeu_note()) {
        kslog("exec: cofeu notu yok (%u bayt): %s\n", elf_len, path);
        return -1;
    }

    int i = find_hole();
    if (i < 0) return -1;
    void* k = kmalloc(KSTACK_SIZE);
    if (!k) return -1;
    int pid = pid_alloc();
    if (pid < 0) { kfree(k); return -1; }

    Process& p = table[i];
    memset(&p, 0, sizeof(p));
    p.pid      = (uint16_t)pid;
    p.state    = P_EMPTY;              /* hazir olana kadar secilemez (timer IRQ'suna karsi) */
    p.kstack   = (uint64_t)k;

    const char* nm = path;
    const char* slash = strrchr(path, '/');
    if (slash) nm = slash + 1;
    int nl = (int)strlen(nm);
    if (nl > 14) nl = 14;
    memcpy(p.name, nm, (size_t)nl);
    p.name[nl] = 0;

    /* once tablolari kur (hata olursa geri al) */
    p.pml4 = alloc_zero_frame();
    p.pdpt = alloc_zero_frame();
    p.pd   = alloc_zero_frame();
    p.pt   = alloc_zero_frame();
    p.user_code_pages = 0;
    if (!p.pml4 || !p.pdpt || !p.pd || !p.pt) {
        kslog("exec: adres alani ayrilamadi (%s)\n", path);
        vm_free(p);
        kfree(k);
        p.state = P_EMPTY; p.pid = 0;
        return -1;
    }
    if (!elf_parse_and_load(p.code_frames, &p.user_code_pages)) {
        kslog("exec: ELF yuklenemedi (%s)\n", path);
        vm_free(p);
        kfree(k);
        p.state = P_EMPTY; p.pid = 0;
        return -1;
    }

    vm_build(p, p.code_frames, p.user_code_pages);
    if (!p.cr3) { kfree(k); p.state = P_EMPTY; p.pid = 0; return -1; }

    p.start_tick = timer_get_ticks();
    p.ctx = build_initial_context2(p, elf_entry);
    p.state = P_READY;                  /* ancak yigin/ctx tam kurulunca secilebilir */
    return (int)p.pid;
}

/* execve: BU surecin adres alanini diskteki ELF ile degistirir. pid/name/kstack
   ayni kalir; eski imaj serbest birakilir, yenisi kurulur ve e_entry'den
   devam edilir. Donen ctx yeni baslangic frame'idir (exec hic donmez). */
extern "C" uint64_t sched_exec_self(uint64_t ctx, const char* path) {
    if (!cur) return ctx;
    Process* self = cur;
    kslog("exec-self: %s pid=%d\n", path, self->pid);

    elf_len = 0;
    if (!fs::read_file(0, path, elf_buf, sizeof(elf_buf), &elf_len)) return ctx;
    if (elf_len < sizeof(Elf64_EhdrL)) return ctx;
    Elf64_EhdrL* eh = (Elf64_EhdrL*)elf_buf;
    if (!elf_is_valid(eh)) return ctx;
    if (!elf_has_cofeu_note()) {
        kslog("exec-self: cofeu imzasi yok (%s)\n", path);
        return ctx;
    }
    /* yeni adres alanini ayri bir Process'te (bellek alanlari) OLUMSUZ
       calisirken kur; basarisizlik olursa eski imaj bozulmadan kalir. */
    Process np;
    memset(&np, 0, sizeof(np));
    np.pml4 = alloc_zero_frame();
    np.pdpt = alloc_zero_frame();
    np.pd   = alloc_zero_frame();
    np.pt   = alloc_zero_frame();
    np.user_code_pages = 0;
    if (!np.pml4 || !np.pdpt || !np.pd || !np.pt) { vm_free(np); return ctx; }
    if (!elf_parse_and_load(np.code_frames, &np.user_code_pages)) { vm_free(np); return ctx; }
    vm_build(np, np.code_frames, np.user_code_pages);
    if (!np.cr3) { vm_free(np); return ctx; }

    /* eski imaji serbest birak, yeni adres alanini ana surece tasi */
    vm_free(*self);
    self->pml4 = np.pml4; self->pdpt = np.pdpt;
    self->pd   = np.pd;   self->pt   = np.pt;
    self->cr3  = np.cr3;
    self->user_code_pages = np.user_code_pages;
    for (int i = 0; i < USER_CODE_MAX_PAGES; i++) self->code_frames[i] = np.code_frames[i];
    for (int k = 0; k < USER_STACK_PAGES; k++)    self->stk_pages[k]   = np.stk_pages[k];

    self->ctx = build_initial_context2(*self, elf_entry);
    kslog("exec-self: OK pid=%d entry=0x%llx\n", self->pid,
          (unsigned long long)elf_entry);
    return self->ctx;
}

extern "C" uint64_t sched_tick(uint64_t ctx) {
    return sched_reschedule(ctx);
}
extern "C" uint64_t sched_reschedule(uint64_t ctx) {
    Process* self = cur;
    wake_sleepers();

    if (!self) {
        if (!sched_ready) return ctx;                /* henuz kullanici moda gecilmedi */
        /* kernel modundayiz: hazir kullanici task varsa gec */
        Process* next = pick_ready(NULL);
        if (!next) return ctx;
        kernel_ctx = ctx;
        kernel_ctx_valid = true;
        cur = next; cur_idx = (int)(next - table);
        cur->state = P_RUNNING;
        cur->preempts++;
        tss_set_rsp0(next->kstack + KSTACK_SIZE);
        write_cr3(next->cr3);
        if (SCHED_DEBUG) kslog("sched k->u pid=%d\n", cur->pid);
        return cur->ctx;
    }

    bool run_again = (self->state == P_RUNNING);
    if (run_again) self->state = P_READY;
    self->preempts++;

    Process* next = pick_ready(run_again ? self : NULL);
    if (!next) {
        /* uyuyan/zombi kimse yok; kernel'e don. Ayrica kernel mode'a INRILIRKEN
           CR3 duzelt: sureci reapledikten sonra eski (freed) pml4 aktif kalirsa
           kernel heap yazimlari freed+geri-donusturulmus tablolardan gecer ve
           page fault uretir (3. exec'te gozlemlenen cr2=0x35e000 #PF). */
        cur = NULL; cur_idx = -1;
        write_cr3(mmio_boot_pml4());
        if (kernel_ctx_valid) return kernel_ctx;
        return ctx;
    }

    self->ctx = ctx;
    cur = next; cur_idx = (int)(next - table);
    cur->state = P_RUNNING;
    tss_set_rsp0(next->kstack + KSTACK_SIZE);
    write_cr3(next->cr3);
    if (SCHED_DEBUG) kslog("sched u->u pid=%d\n", cur->pid);
    return cur->ctx;
}

extern "C" uint64_t syscall_handle(uint64_t ctx) {
    uint64_t* r = (uint64_t*)ctx;
    uint64_t n  = r[OFF_RAX];
    uint64_t a0 = r[OFF_RDI], a1 = r[OFF_RSI], a2 = r[OFF_RDX];

    if (!cur) { r[OFF_RAX] = (uint64_t)-1; return ctx; }

    switch (n) {
    case SYS_EXIT: {
        cur->exitcode = (uint32_t)a0;
        cur->state    = P_ZOMBIE;
        r[OFF_RAX]    = 0;
        return sched_reschedule(ctx);
    }
    case SYS_SLEEP: {
        if (a0) {
            cur->state    = P_SLEEPING;
            cur->waketick = timer_get_ticks() + a0 / 10u;   /* 100Hz */
            r[OFF_RAX]    = 0;
            return sched_reschedule(ctx);
        }
        r[OFF_RAX] = 0;
        break;
    }
    case SYS_YIELD:
        r[OFF_RAX] = 0;
        return sched_reschedule(ctx);
    case SYS_GETPID:
        r[OFF_RAX] = cur->pid;
        break;
    case SYS_GETTICKS:
        r[OFF_RAX] = timer_get_ticks();
        break;
    case SYS_PUTC:
        if (a0 <= 0xFF) {
            vga_putc((char)a0);
            serial_putc((char)a0);
        }
        r[OFF_RAX] = 0;
        break;
    case SYS_PUTSN: {
        const char* s = (const char*)a0;
        if (a1 > 1024 || !uaddr_ok(a0, a1)) {
            r[OFF_RAX] = (uint64_t)-1;
            break;
        }
        for (uint64_t i = 0; i < a1; i++) {
            vga_putc(s[i]);
            serial_putc(s[i]);
        }
        r[OFF_RAX] = (uint64_t)a1;
        break;
    }
    case SYS_FORK: {
        if (!cur->cr3 || !img_pages) { r[OFF_RAX] = (uint64_t)-1; break; }
        int slot = find_hole();
        if (slot < 0) { r[OFF_RAX] = (uint64_t)-1; break; }
        void* k = kmalloc(KSTACK_SIZE);
        if (!k) { r[OFF_RAX] = (uint64_t)-1; break; }
        int pid = pid_alloc();
        if (pid < 0) { kfree(k); r[OFF_RAX] = (uint64_t)-1; break; }

        Process& c = table[slot];
        memset(&c, 0, sizeof(c));
        c.pid      = (uint16_t)pid;
        c.state    = P_EMPTY;              /* kurulum bitene kadar secilemez */
        c.kstack   = (uint64_t)k;
        memcpy(c.name, cur->name, 15);

        vm_new(c);
        if (!c.cr3) { kfree(k); c.pid = 0; c.state = P_EMPTY; break; }

        /* ana surecin yigincik icerigini cocuga kopyala (izole ozel sayfalar) */
        for (int s = 0; s < USER_STACK_PAGES; s++)
            if (cur->stk_pages[s] && c.stk_pages[s])
                memcpy((void*)c.stk_pages[s], (void*)cur->stk_pages[s], 4096);

        c.ctx = build_fork_context(c, r);
        c.state = P_READY;                 /* ancak ctx kurulunca secilebilir */
        r[OFF_RAX] = c.pid;
        break;
    }
    case SYS_GETNAME: {
        if (!uaddr_ok(a0, 15)) { r[OFF_RAX] = (uint64_t)-1; break; }
        char* dst = (char*)a0;
        for (int i = 0; i < 15; i++) dst[i] = cur->name[i];   /* NUL dolgulu */
        r[OFF_RAX] = 0;
        break;
    }
    case SYS_FSWRITE:
    case SYS_FSAPPEND: {
        char path[96];
        if (!copy_user_path(a0, path, sizeof(path)) ||
            a2 > 2048 || !uaddr_ok(a1, a2)) { r[OFF_RAX] = (uint64_t)-1; break; }
        bool ok = (n == SYS_FSWRITE)
                  ? fs::write_file(0, path, (const void*)a1, (uint32_t)a2)
                  : fs::append_file(0, path, (const void*)a1, (uint32_t)a2);
        r[OFF_RAX] = ok ? (uint64_t)a2 : (uint64_t)-1;
        break;
    }
    case SYS_FSREAD: {
        char path[96];
        if (!copy_user_path(a0, path, sizeof(path)) ||
            !uaddr_ok(a1, a2) || a2 > 4096) { r[OFF_RAX] = (uint64_t)-1; break; }
        uint32_t got = 0;
        bool ok = fs::read_file(0, path, (void*)a1, (uint32_t)a2, &got);
        r[OFF_RAX] = ok ? (uint64_t)got : (uint64_t)-1;
        break;
    }
    case SYS_FSSTAT: {
        char path[96];
        if (!copy_user_path(a0, path, sizeof(path)) ||
            !uaddr_ok(a1, sizeof(fs::EntryInfo))) { r[OFF_RAX] = (uint64_t)-1; break; }
        fs::EntryInfo st;
        if (!fs::stat(0, path, &st)) { r[OFF_RAX] = (uint64_t)-1; break; }
        fs::EntryInfo* d = (fs::EntryInfo*)a1;
        d->type_ = st.type_;
        d->size_ = st.size_;
        for (int i = 0; i < 32; i++) d->name_[i] = st.name_[i];
        r[OFF_RAX] = 0;
        break;
    }
    case SYS_GETCH: {
        bool any = keyboard_has_char() || serial_has_char();
        r[OFF_RAX] = any ? 1 : 0;
        break;
    }
    case SYS_FSGETC: {
        char c;
        if (keyboard_has_char())                       c = keyboard_getc();
        else if (serial_has_char())                    c = serial_getc();
        else { r[OFF_RAX] = (uint64_t)-1; break; }
        r[OFF_RAX] = (uint8_t)c;
        break;
    }
    case SYS_WAIT: {
        uint16_t want = (uint16_t)a0;
        int found = -1;
        for (int i = 0; i < MAX_PROC; i++) {
            Process& q = table[i];
            if (q.state != P_ZOMBIE) continue;
            if (want && q.pid != want) continue;
            found = i; break;
        }
        if (found < 0) { r[OFF_RAX] = (uint64_t)-1; break; }
        r[OFF_RAX] = table[found].exitcode;
        vm_free(table[found]);
        if (table[found].kstack) kfree((void*)table[found].kstack);
        table[found].state = P_EMPTY;
        table[found].pid   = 0;
        break;
    }
    case SYS_EXEC: {
        char path[96];
        if (!copy_user_path(a0, path, sizeof(path))) { r[OFF_RAX] = (uint64_t)-1; break; }
        return sched_exec_self(ctx, path);      /* surecin imajini degistir, donmez */
    }
    case SYS_UDPSOCK:
        r[OFF_RAX] = (uint64_t)net_udp_socket();
        break;
    case SYS_UDPBIND:
        r[OFF_RAX] = net_udp_bind((int)a0, (uint16_t)a1) ? 0 : (uint64_t)-1;
        break;
    case SYS_UDPSENDTO: {
        uint64_t a3 = r[OFF_RCX];
        uint16_t dport = (uint16_t)(a2 & 0xFFFF);
        uint16_t dlen  = (uint16_t)(a2 >> 16);
        if (dlen > 1472 || !uaddr_ok(a3, dlen)) { r[OFF_RAX] = (uint64_t)-1; break; }
        int n = net_udp_send_to((int)a0, (uint32_t)a1, dport,
                                (const uint8_t*)a3, dlen);
        r[OFF_RAX] = (n >= 0) ? (uint64_t)n : (uint64_t)-1;
        break;
    }
    case SYS_UDPWAIT:
        r[OFF_RAX] = net_udp_wait((int)a0, (uint32_t)a1) ? 1 : 0;
        break;
    case SYS_UDPRECVFROM: {
        uint64_t a3 = r[OFF_RCX];
        if (!uaddr_ok(a1, a2) || a2 > 1500) { r[OFF_RAX] = (uint64_t)-1; break; }
        if (a3 && !uaddr_ok(a3, 6)) { r[OFF_RAX] = (uint64_t)-1; break; }
        uint32_t sip = 0, sp = 0;
        int n = net_udp_recv_from((int)a0, (uint8_t*)a1, (uint32_t)a2,
                                  a3 ? &sip : NULL, a3 ? (uint16_t*)&sp : NULL);
        if (n < 0) { r[OFF_RAX] = (uint64_t)-1; break; }
        if (a3) {
            *(uint32_t*)a3     = sip;
            *(uint16_t*)(a3+4) = (uint16_t)sp;
        }
        r[OFF_RAX] = (uint64_t)n;
        break;
    }
    case SYS_UDPCLOSE:
        r[OFF_RAX] = net_udp_close((int)a0) ? 0 : (uint64_t)-1;
        break;
    case SYS_TCPSOCK:
        r[OFF_RAX] = (uint64_t)net_socket();
        break;
    case SYS_TCPLISTEN:
        r[OFF_RAX] = net_tcp_listen((int)a0, (uint16_t)a1) ? 0 : (uint64_t)-1;
        break;
    case SYS_TCPPENDING:
        r[OFF_RAX] = net_tcp_pending((int)a0);
        break;
    case SYS_TCPCONNECT: {
        IntrLatch il;
        bool ok = net_tcp_connect((int)a0, (uint32_t)a1, (uint16_t)a2);
        r[OFF_RAX] = ok ? 0 : (uint64_t)-1;
        break;
    }
    case SYS_TCPACCEPT: {
        IntrLatch il;
        int c = net_tcp_accept((int)a0, (uint32_t)a1);
        r[OFF_RAX] = (c >= 0) ? (uint64_t)c : (uint64_t)-1;
        break;
    }
    case SYS_TCPSEND: {
        int len = (a2 > 1500) ? 1500 : (int)a2;
        if (len < 0 || !uaddr_ok(a1, len)) { r[OFF_RAX] = (uint64_t)-1; break; }
        IntrLatch il;
        bool ok = net_tcp_send((int)a0, (const uint8_t*)a1, (uint16_t)len);
        r[OFF_RAX] = ok ? (uint64_t)len : (uint64_t)-1;
        break;
    }
    case SYS_TCPWAIT: {
        IntrLatch il;
        net_tcp_wait((int)a0, (uint32_t)a1);
        bool any = net_tcp_done((int)a0) || net_tcp_err((int)a0) ||
                   net_tcp_pending((int)a0) > 0;
        r[OFF_RAX] = any ? 1 : 0;
        break;
    }
    case SYS_TCPRECV: {
        uint64_t a3 = r[OFF_RCX];
        if (a2 > 4096 || !uaddr_ok(a1, a2)) { r[OFF_RAX] = (uint64_t)-1; break; }
        IntrLatch il;
        uint32_t n = net_tcp_recv_some((int)a0, (uint8_t*)a1, (uint32_t)a2, (uint32_t)a3);
        if (n == 0) {
            if (net_tcp_err((int)a0))  r[OFF_RAX] = (uint64_t)-1;
            else if (net_tcp_done((int)a0)) r[OFF_RAX] = (uint64_t)-2;
            else r[OFF_RAX] = 0;
        } else {
            r[OFF_RAX] = (uint64_t)n;
        }
        break;
    }
    case SYS_TCPCLOSE: {
        IntrLatch il;
        net_tcp_close((int)a0);
        r[OFF_RAX] = 0;
        break;
    }
    default:
        r[OFF_RAX] = (uint64_t)-1;
        break;
    }
    return ctx;
}

extern "C" uint64_t sched_userpf_kill(uint64_t ctx) {
    if (!cur) return ctx;
    kslog("USER PF pid=%d olduruldu\n", cur->pid);
    kprintf("\n## surec #%u olduruldu (kullanici bellek hatasi)\n", cur->pid);
    cur->exitcode = 128 + 14;
    cur->state    = P_ZOMBIE;
    return sched_reschedule(ctx);
}

extern "C" void sched_list(void) {
    kprintf("PID    HEX   ST NAME           PRM  TIME  MEM(KB)  EXIT\n");
    uint64_t now = timer_get_ticks();
    for (int i = 0; i < MAX_PROC; i++) {
        const Process& p = table[i];
        const char* st = "????";
        switch (p.state) {
        case P_READY:    st = "R"; break;
        case P_RUNNING:  st = "R"; break;
        case P_SLEEPING: st = "S"; break;
        case P_ZOMBIE:   st = "Z"; break;
        default:         continue;
        }
        uint32_t memkb = (uint32_t)(p.user_code_pages + USER_STACK_PAGES + 4) * 4u;
        uint64_t secs  = (now - p.start_tick) / 100u;
        if (p.state == P_ZOMBIE) secs = 0;
        kprintf("%-5u 0x%04X  %-2s %-14s %-4lu %5llus  %6u    %lu\n",
                p.pid, p.pid, st, p.name, (unsigned long)p.preempts,
                (unsigned long long)secs, memkb, (unsigned long)p.exitcode);
    }
}

extern "C" int sched_kill(uint16_t pid) {
    int i = find_by_pid(pid);
    if (i < 0) return -1;
    Process& p = table[i];
    if (&p == cur) return -1;               /* calisan sureci oldurme */
    vm_free(p);
    if (p.kstack) kfree((void*)p.kstack);
    p.state = P_EMPTY;
    p.pid   = 0;
    return 0;
}

extern "C" int sched_wait(uint16_t pid) {
    for (int i = 0; i < MAX_PROC; i++) {
        Process& q = table[i];
        if (q.state != P_ZOMBIE) continue;
        if (pid && q.pid != pid) continue;
        int ec = (int)q.exitcode;
        vm_free(q);
        if (q.kstack) kfree((void*)q.kstack);
        q.state = P_EMPTY;
        q.pid   = 0;
        return ec;
    }
    return -1;
}

extern "C" int sched_count(void) {
    int c = 0;
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state != P_EMPTY && table[i].state != P_ZOMBIE) c++;
    return c;
}