#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "sched.h"

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
    uint64_t waketick;
    uint64_t preempts;
    uint32_t exitcode;
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
               pd[0]->pt; pt[] = imaj (RO paylasilan) + yigincik (RW ozel). */
void vm_new(Process& p) {
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
    pdp[0]   = p.pt | 0x7;

    for (int i = 0; i < img_pages; i++)
        pte[i] = img_frames[i] | 0x5;     /* P|U, salt-okunur (paylasilan kod) */

    for (int k = 0; k < USER_STACK_PAGES; k++) {
        uint64_t f = alloc_zero_frame();
        if (!f) break;
        p.stk_pages[k] = f;
        int idx = (int)(((USER_STACK_TOP >> 12) - 1 - k) & 0x1FFu);  /* PT index */
        pte[idx] = f | 0x7;                                /* P|RW|U */
    }
    p.cr3 = p.pml4;
}

void vm_free(Process& p) {
    for (int k = 0; k < USER_STACK_PAGES; k++)
        if (p.stk_pages[k]) { pmm_free_frame(p.stk_pages[k]); p.stk_pages[k] = 0; }
    if (p.pt)   { pmm_free_frame(p.pt);   p.pt = 0; }
    if (p.pd)   { pmm_free_frame(p.pd);   p.pd = 0; }
    if (p.pdpt) { pmm_free_frame(p.pdpt); p.pdpt = 0; }
    if (p.pml4) { pmm_free_frame(p.pml4); p.pml4 = 0; }
    p.cr3 = 0;
}

/* isr_common'un erteledigi frame: r15 push'tan iretq frame'ine kadar */
uint64_t build_initial_context(Process& p) {
    uint64_t* sp = (uint64_t*)(p.kstack + KSTACK_SIZE);
    *--sp = UDS;                        /* [21] ss        */
    *--sp = USER_STACK_TOP;             /* [20] usr rsp    */
    *--sp = 0x202;                      /* [19] rflags IF  */
    *--sp = UCS;                        /* [18] cs         */
    *--sp = USER_ENTRY_ADDR;            /* [17] rip (elf giris noktasi) */
    *--sp = 0;                          /* [16] err        */
    *--sp = 0;                          /* [15] vec        */
    for (int i = 14; i >= 0; i--) *--sp = 0;   /* [14..0] regler */
    return (uint64_t)sp;
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
    p.state    = P_READY;
    p.kstack   = (uint64_t)k;

    int nl = (int)strlen(name);
    if (nl > 14) nl = 14;
    memcpy(p.name, name, (size_t)nl);
    p.name[nl] = 0;

    vm_new(p);
    if (!p.cr3) { kfree(k); p.state = P_EMPTY; p.pid = 0; return -1; }

    p.ctx = build_initial_context(p);
    return (int)p.pid;
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
        /* uyuyan/zombi kimse yok; kernel'e don (kernel kimlik haritasi her
           proseste mevcut oldugundan CR3 degismeden calisabilir) */
        cur = NULL; cur_idx = -1;
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
    uint64_t a0 = r[OFF_RDI], a1 = r[OFF_RSI];

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
        c.state    = P_READY;
        c.kstack   = (uint64_t)k;
        memcpy(c.name, cur->name, 15);

        vm_new(c);
        if (!c.cr3) { kfree(k); c.pid = 0; c.state = P_EMPTY; break; }

        /* ana surecin yigincik icerigini cocuga kopyala (izole ozel sayfalar) */
        for (int s = 0; s < USER_STACK_PAGES; s++)
            if (cur->stk_pages[s] && c.stk_pages[s])
                memcpy((void*)c.stk_pages[s], (void*)cur->stk_pages[s], 4096);

        c.ctx = build_fork_context(c, r);
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
    kprintf("PID    HEX   ST NAME           PRM\n");
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
        kprintf("%-5u 0x%04X  %-2s %-14s %lu\n",
                p.pid, p.pid, st, p.name, (unsigned long)p.preempts);
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

extern "C" int sched_count(void) {
    int c = 0;
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state != P_EMPTY && table[i].state != P_ZOMBIE) c++;
    return c;
}