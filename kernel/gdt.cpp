#include "kernel.h"
#include "x86.h"

namespace {

struct __attribute__((packed)) GDTDesc {
    uint16_t limit;
    uint64_t base;
};

__attribute__((aligned(8)))
uint64_t gdt[8];

/* context 'Su siralama: 0x00 null, 0x08 kod0, 0x10 veri0, 0x18 kod0(boot),
   0x20 veri3, 0x28 kod3, 0x30 TSS */
constexpr uint16_t SEL_KDATA = 0x10;

struct __attribute__((packed)) TSS {
    uint32_t reserved1;
    uint64_t rsp0, rsp1, rsp2;
    uint64_t reserved2;
    uint64_t ist[7];
    uint64_t reserved3;
    uint16_t reserved4;
    uint16_t iopb;
};
static_assert(sizeof(TSS) == 104, "tss boyutu");

__attribute__((aligned(16)))
TSS tss;

void tss_write_desc(void) {
    uint64_t base  = (uint64_t)&tss;
    uint64_t limit = sizeof(TSS) - 1;   /* 103 */
    gdt[6] = (limit & 0xFFFFu)
           | ((base & 0xFFFFFFu) << 16)
           | (0x89ull << 40)                          /* available 64-bit TSS */
           | (((limit >> 16) & 0xFu) << 48)
           | (((base >> 24) & 0xFFu) << 56);
    gdt[7] = base >> 32;
}

void reload_cs(void) {
    asm volatile(
        "pushq $0x08\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n" ::: "rax", "memory");
}

} /* namespace */

extern char __kstack_top;

extern "C" void tss_set_rsp0(uint64_t rsp0) { tss.rsp0 = rsp0; }

extern "C" void gdt_init(void) {
    gdt[0] = 0x0000000000000000ULL;              /* null   0x00 */
    gdt[1] = 0x00AF9A000000FFFFULL;              /* kod    0x08 (ring0) */
    gdt[2] = 0x00CF92000000FFFFULL;              /* veri   0x10 (ring0) */
    gdt[3] = 0x00AF9A000000FFFFULL;              /* kod    0x18 (boot icin) */
    gdt[4] = 0x00CFF2000000FFFFULL;              /* veri3  0x20 */
    gdt[5] = 0x00AFFA000000FFFFULL;              /* kod3   0x28 */
    tss_write_desc();

    memset(&tss, 0, sizeof(tss));
    tss.iopb = sizeof(TSS);                      /* io bitmapi yok */
    tss.rsp0 = (uint64_t)&__kstack_top;          /* ilk deger: kernel yigini */

    GDTDesc d;
    d.limit = sizeof(gdt) - 1;
    d.base  = (uint64_t)gdt;
    asm volatile("lgdt %0" : : "m"(d) : "memory");
    reload_cs();
    asm volatile(
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n" ::: "ax");
    asm volatile("mov $0x30, %%ax\nltr %%ax" ::: "ax");
}