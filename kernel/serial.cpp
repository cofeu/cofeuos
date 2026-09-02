#include "kernel.h"
#include "x86.h"

namespace {
constexpr uint16_t COM1 = 0x3F8;
}

extern "C" void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);      /* 115200 baud */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);      /* 8N1 */
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

extern "C" void serial_putc(char c) {
    for (int i = 0; i < 100000; i++)
        if (inb(COM1 + 5) & 0x20) break;
    outb(COM1, (uint8_t)c);
}

extern "C" void serial_write(const char* s) {
    while (*s) {
        if (*s == '\n') serial_putc('\r');
        serial_putc(*s++);
    }
}