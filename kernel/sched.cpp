#include "kernel.h"
#include "x86.h"
#include "sched.h"

#define SCHED_DEBUG 0

namespace {

/* ---- proses tablosu ---- */
enum { P_EMPTY = 0, P_READY = 1, P_RUNNING = 2, P_SLEEPING = 3, P_ZOMBIE = 4 };

constexpr int    MAX_PROC    = 32;
constexpr uint16_t UCS         = 0x2B;   /* user kod 0x28 | RPL3 */
constexpr uint16_t UDS         = 0x23;   /* user veri 0x20 | RPL3 */
constexpr uint64_t USER_LIM    = 0x40000000ull;  /* 1GB kimlik aralik siniri */
constexpr size_t KSTACK_SIZE = 8192;
constexpr size_t USTACK_SIZE = 8192;

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
    uint64_t ctx;          /* kernel yigininda saklanan frame (isr sonrasi rsp) */
    uint64_t kstack, usp;  /* taban adresleri (free icin) */
    uint64_t waketick;
    uint64_t preempts;     /* kaydirilma sayisi */
    uint32_t exitcode;
    char     tag;
    uint32_t period;
    uint32_t iters;
};

struct ProcDemo {
    char     tag;
    uint32_t period;
    uint32_t iters;
};

Process     table[MAX_PROC];
ProcDemo    demo_cfg[MAX_PROC];
Process*    cur = NULL;
int         cur_idx = -1;
uint64_t    kernel_ctx = 0;
bool        kernel_ctx_valid = false;

/* ---- PID ------------ *max
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

int find_hole(void) {
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state == P_EMPTY) return i;
    /* zombi slotlari da geri kazan: stack'lerini birak, tabloyu bosalt */
    for (int i = 0; i < MAX_PROC; i++) {
        if (table[i].state != P_ZOMBIE) continue;
        Process& p = table[i];
        if (p.kstack) kfree((void*)p.kstack);
        if (p.usp)    kfree((void*)p.usp);
        p.kstack = p.usp = 0;
        p.pid    = 0;
        p.state  = P_EMPTY;
        return i;
    }
    return -1;
}

/* isr_common'un erteledigi frame: r15 push'tan iretq frame'ine kadar */
uint64_t build_initial_context(Process* p, void (*entry)(uint64_t), uint64_t arg) {
    uint64_t* sp = (uint64_t*)(p->kstack + KSTACK_SIZE);
    *--sp = UDS;                        /* [21] ss        */
    *--sp = p->usp + USTACK_SIZE;       /* [20] usr rsp    */
    *--sp = 0x202;                      /* [19] rflags IF  */
    *--sp = UCS;                        /* [18] cs         */
    *--sp = (uint64_t)entry;            /* [17] rip        */
    *--sp = 0;                          /* [16] err        */
    *--sp = 0;                          /* [15] vec        */
    *--sp = 0;                          /* [14] rax        */
    *--sp = 0;                          /* [13] rcx        */
    *--sp = 0;                          /* [12] rdx        */
    *--sp = 0;                          /* [11] rbx        */
    *--sp = 0;                          /* [10] rbp        */
    *--sp = 0;                          /* [ 9] rsi        */
    *--sp = arg;                        /* [ 8] rdi        */
    *--sp = 0;                          /* [ 7] r8         */
    *--sp = 0;                          /* [ 6] r9         */
    *--sp = 0;                          /* [ 5] r10        */
    *--sp = 0;                          /* [ 4] r11        */
    *--sp = 0;                          /* [ 3] r12        */
    *--sp = 0;                          /* [ 2] r13        */
    *--sp = 0;                          /* [ 1] r14        */
    *--sp = 0;                          /* [ 0] r15        */
    return (uint64_t)sp;
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

uint64_t sched_reschedule(uint64_t ctx) {
    Process* self = cur;
    wake_sleepers();

    if (!self) {
        /* kernel modundayiz: hazir kullanici task varsa gec */
        Process* next = pick_ready(NULL);
        if (!next) return ctx;
        kernel_ctx = ctx;
        kernel_ctx_valid = true;
        cur = next; cur_idx = (int)(next - table);
        cur->state = P_RUNNING;
        cur->preempts++;
        tss_set_rsp0(next->kstack + KSTACK_SIZE);
        if (SCHED_DEBUG) kslog("sched k->u pid=%d\n", cur->pid);
        return cur->ctx;
    }

    bool run_again = (self->state == P_RUNNING);
    if (run_again) self->state = P_READY;
    self->preempts++;

    Process* next = pick_ready(run_again ? self : NULL);
    if (!next) {
        /* uyuyan/zombi kimse yok; kernel'e don */
        cur = NULL; cur_idx = -1;
        if (kernel_ctx_valid) return kernel_ctx;
        return ctx;
    }

    self->ctx = ctx;
    cur = next; cur_idx = (int)(next - table);
    cur->state = P_RUNNING;
    tss_set_rsp0(next->kstack + KSTACK_SIZE);
    if (SCHED_DEBUG) kslog("sched u->u pid=%d\n", cur->pid);
    return cur->ctx;
}

void user_print_hex(char* buf, int* n, uint32_t v) {
    const char* h = "0123456789ABCDEF";
    buf[(*n)++] = '0'; buf[(*n)++] = 'x';
    buf[(*n)++] = h[(v >> 12) & 0xF];
    buf[(*n)++] = h[(v >> 8) & 0xF];
    buf[(*n)++] = h[(v >> 4) & 0xF];
    buf[(*n)++] = h[v & 0xF];
}

void user_print_dec(char* buf, int* n, uint64_t v) {
    char tmp[20]; int tn = 0;
    do { tmp[tn++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (tn) buf[(*n)++] = tmp[--tn];
}

/* ---- ring3'te kosan demo islemler ---- */
static void user_process_entry(uint64_t slot);

} /* namespace */

extern "C" void sched_init(void) {
    for (int i = 0; i < MAX_PROC; i++) {
        table[i].state   = P_EMPTY;
        table[i].pid     = 0;
        demo_cfg[i].tag  = '?';
        demo_cfg[i].period = 200;
        demo_cfg[i].iters  = 0;
    }
    cur = NULL; cur_idx = -1;
    kernel_ctx = 0; kernel_ctx_valid = false;
}

extern "C" int sched_spawn(const char* name, char tag, uint32_t period_ms, uint32_t iters) {
    int i = find_hole();
    if (i < 0) return -1;

    void* k = kmalloc(KSTACK_SIZE);
    void* u = kmalloc(USTACK_SIZE);
    if (!k || !u) {
        if (k) kfree(k);
        if (u) kfree(u);
        return -1;
    }

    int pid = pid_alloc();
    if (pid < 0) { kfree(k); kfree(u); return -1; }

    Process& p = table[i];
    p.pid     = (uint16_t)pid;
    p.state   = P_READY;
    p.kstack  = (uint64_t)k;
    p.usp     = (uint64_t)u;
    p.waketick= 0;
    p.preempts= 0;
    p.exitcode= 0;
    p.tag     = tag;
    p.period  = period_ms ? period_ms : 200;
    p.iters   = iters;

    int nl = (int)strlen(name);
    if (nl > 14) nl = 14;
    memcpy(p.name, name, (size_t)nl);
    p.name[nl] = 0;

    demo_cfg[i].tag    = tag;
    demo_cfg[i].period = p.period;
    demo_cfg[i].iters  = iters;

    p.ctx = build_initial_context(&p, user_process_entry, (uint64_t)i);
    return (int)p.pid;
}

extern "C" uint64_t sched_tick(uint64_t ctx) {
    return sched_reschedule(ctx);
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
        if (a1 > 1024 || (uint64_t)s < 0x1000 ||
            (uint64_t)s + a1 > USER_LIM) {
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
    default:
        r[OFF_RAX] = (uint64_t)-1;
        break;
    }
    return ctx;
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
    table[i].state = P_EMPTY;
    table[i].pid   = 0;
    if (p.kstack) kfree((void*)p.kstack);
    if (p.usp)    kfree((void*)p.usp);
    return 0;
}

extern "C" int sched_count(void) {
    int c = 0;
    for (int i = 0; i < MAX_PROC; i++)
        if (table[i].state != P_EMPTY && table[i].state != P_ZOMBIE) c++;
    return c;
}

namespace {

static void user_process_entry(uint64_t slot) {
    char buf[96];
    uint32_t cnt = 0;
    for (;;) {
        const ProcDemo& d = demo_cfg[slot];
        uint64_t pid = do_syscall(SYS_GETPID, 0, 0, 0);
        uint64_t t   = do_syscall(SYS_GETTICKS, 0, 0, 0);

        int n = 0;
        buf[n++] = d.tag;
        buf[n++] = ' '; buf[n++] = 'p'; buf[n++] = 'i'; buf[n++] = 'd';
        user_print_hex(buf, &n, (uint32_t)pid);
        buf[n++] = ' '; buf[n++] = 'c'; buf[n++] = '=';
        buf[n++] = (char)('0' + (cnt % 10));
        buf[n++] = ' '; buf[n++] = 't'; buf[n++] = '=';
        user_print_dec(buf, &n, t);
        buf[n++] = '\n';

        do_syscall(SYS_PUTSN, (uint64_t)buf, (uint64_t)n, 0);

        cnt++;
        if (d.iters && cnt >= d.iters)
            do_syscall(SYS_EXIT, (uint64_t)(cnt % 10), 0, 0);

        do_syscall(SYS_SLEEP, d.period, 0, 0);
    }
}

} /* namespace */