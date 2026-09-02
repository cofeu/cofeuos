#include "kernel.h"
#include "x86.h"

extern "C" uint64_t isr_stub_table[256];

namespace {

struct __attribute__((packed)) IDTGate {
    uint16_t off0;
    uint16_t sel;
    uint8_t ist;
    uint8_t attr;
    uint16_t off1;
    uint32_t off2;
    uint32_t zero;
};

struct __attribute__((packed)) IDTR {
    uint16_t limit;
    uint64_t base;
};

IDTGate idt[256];
IDTR idtr;

} /* namespace */

extern "C" void idt_init(void) {
    for (int i = 0; i < 256; i++) {
        uint64_t off = isr_stub_table[i];
        idt[i].off0 = (uint16_t)(off & 0xFFFF);
        idt[i].sel  = 0x08;
        idt[i].ist  = 0;
        idt[i].attr = 0x8E;               /* present, ring0, interrupt gate */
        idt[i].off1 = (uint16_t)((off >> 16) & 0xFFFF);
        idt[i].off2 = (uint32_t)(off >> 32);
        idt[i].zero = 0;
    }
    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint64_t)idt;
    asm volatile("lidt %0" : : "m"(idtr) : "memory");
}