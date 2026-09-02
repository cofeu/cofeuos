#include "kernel.h"

namespace {

struct __attribute__((packed)) GDTDesc {
    uint16_t limit;
    uint64_t base;
};

__attribute__((aligned(8)))
uint64_t gdt[3] = {
    0x0000000000000000ULL,  /* null        */
    0x00AF9A000000FFFFULL,  /* 0x08 : 64-bit kod */
    0x00AF92000000FFFFULL,  /* 0x10 : 64-bit veri */
};

void reload_cs(void) {
    asm volatile(
        "pushq $0x08\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        ::: "rax", "memory");
}

} /* namespace */

extern "C" void gdt_init(void) {
    GDTDesc d;
    d.limit = sizeof(gdt) - 1;
    d.base = (uint64_t)gdt;
    asm volatile("lgdt %0" : : "m"(d) : "memory");
    reload_cs();
    asm volatile(
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n"
        ::: "ax");
}