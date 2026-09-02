#pragma once
/* x86 port / CPU yardimcilar */

#include "kernel.h"

static inline void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline void outw(uint16_t port, uint16_t val) {
    asm volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t v;
    asm volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline uint16_t inw(uint16_t port) {
    uint16_t v;
    asm volatile("inw %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void io_wait(void) {
    asm volatile("outb %%al, $0x80" : : "a"((uint8_t)0));
}
static inline void insl(uint16_t port, void* dst, uint32_t count) {
    asm volatile("cld; rep insl" : "+D"(dst) : "d"(port), "c"(count) : "memory");
}
static inline void outsl(uint16_t port, const void* src, uint32_t count) {
    asm volatile("cld; rep outsl" : "+S"(src) : "d"(port), "c"(count) : "memory");
}

static inline void cpu_cli(void) { asm volatile("cli"); }
static inline void cpu_sti(void) { asm volatile("sti"); }
static inline void cpu_hlt(void) { asm volatile("hlt"); }

static inline uint64_t read_rflags(void) {
    uint64_t f;
    asm volatile("pushfq; popq %0" : "=r"(f));
    return f;
}

static inline uint64_t read_cr3(void) {
    uint64_t v;
    asm volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

static inline void write_cr3(uint64_t v) {
    asm volatile("mov %0, %%cr3" : : "r"(v) : "memory");
}