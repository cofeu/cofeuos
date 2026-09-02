#pragma once

#include "kernel.h"

/* ---- syscall kuksanlari (int 0x80, DPL3) ----
   rax = numara, rdi/rsi/rdx = arguman, donus rax'te */
#define SYS_EXIT      1
#define SYS_SLEEP     2
#define SYS_YIELD     3
#define SYS_GETPID    4
#define SYS_GETTICKS  5
#define SYS_PUTC      6
#define SYS_PUTSN     7

extern "C" {

void   sched_init(void);
int    sched_spawn(const char* name, char tag, uint32_t period_ms, uint32_t iters);
uint64_t sched_tick(uint64_t ctx);   /* zamanlayici: dondurdugu ctx'e gecilir */
uint64_t syscall_handle(uint64_t ctx);
void   sched_list(void);
int    sched_kill(uint16_t pid);
int    sched_count(void);

}

/* ---- ring3 syscall yardimcisi (kullanici kodu iceride kullanir) ---- */
static inline uint64_t do_syscall(uint64_t n, uint64_t a, uint64_t b, uint64_t c) {
    uint64_t r;
    asm volatile("int $0x80"
                 : "=a"(r)
                 : "a"(n), "D"(a), "S"(b), "d"(c)
                 : "rcx", "r11", "memory");
    return r;
}