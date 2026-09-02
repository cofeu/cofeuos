#include "kernel.h"
#include "x86.h"

namespace {
volatile uint64_t ticks = 0;
volatile uint32_t seconds = 0;
}

extern "C" void timer_init(void) {
    outb(0x43, 0x34);
    uint16_t divisor = 11932;   /* ~100Hz */
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)(divisor >> 8));
    ticks = 0;
    seconds = 0;
}

extern "C" uint64_t timer_get_ticks(void) {
    return ticks;
}

extern "C" uint64_t timer_get_seconds(void) {
    return seconds;
}

extern "C" void timer_irq(void) {
    ticks++;
    if (ticks % 100 == 0) seconds++;
}