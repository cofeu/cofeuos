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
#define SYS_FORK      8
#define SYS_GETNAME   9
#define SYS_FSWRITE  10   /* write_file  (mutlak yol) : a0=yol a1=veri a2=len */
#define SYS_FSAPPEND 11   /* append_file (mutlak yol) : a0=yol a1=veri a2=len */
#define SYS_FSREAD   12   /* read_file   (mutlak yol) : a0=yol a1=buf a2=maxlen */
#define SYS_FSSTAT   13   /* stat: a0=yol a1=EntryInfo* -> rax=boyut, tip rc */
#define SYS_GETCH    14   /* a0=1: bu yana kuyrukta karakter var mi? rax=1/0 */
#define SYS_FSGETC   15   /* stdin (klavye+serial) tek karakter, yoksa -1 */
#define SYS_WAIT     16   /* a0=child pid (0=herhangi) -> rax=exit code, -1 yok */
#define SYS_EXEC     17   /* a0=yol: bu sureci elfla degistir (execve) */

/* ---- UDP soket syscall'lari (int $0x80, 4 arguman: rdi, rsi, rdx, rcx) ---- */
#define SYS_UDPSOCK     18   /* a0=0               -> rax=fd veya -1 */
#define SYS_UDPBIND     19   /* a0=fd a1=port      -> 0 veya -1 (0=otomatik) */
#define SYS_UDPSENDTO   20   /* a0=fd a1=ip a2=port|(len<<16) a3=data -> bayt veya -1 */
#define SYS_UDPWAIT     21   /* a0=fd a1=tick(10ms) -> 1 veri var / 0 zaman asimi */
#define SYS_UDPRECVFROM 22   /* a0=fd a1=out a2=cap a3=&{ip4,port2} (0=meta yok) -> bayt */
#define SYS_UDPCLOSE    23   /* a0=fd              -> 0 veya -1 */

extern "C" {

void   sched_init(void);
void   sched_go(void);                       /* spawn'lardan sonra cagrilir */
int    sched_spawn(const char* name);
int    sched_exec_file(const char* path);    /* diskten ELF calistir (run) */
uint64_t sched_exec_self(uint64_t ctx, const char* path); /* bu sureci elfla degistir */
uint64_t sched_tick(uint64_t ctx);   /* zamanlayici: dondurdugu ctx'e gecilir */
uint64_t sched_reschedule(uint64_t ctx);
uint64_t syscall_handle(uint64_t ctx);
uint64_t sched_userpf_kill(uint64_t ctx);
void   sched_list(void);
int    sched_kill(uint16_t pid);
int    sched_wait(uint16_t pid);
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