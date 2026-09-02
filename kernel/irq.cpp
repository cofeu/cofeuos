#include "kernel.h"
#include "x86.h"

namespace {

void mask_and_disable_all(void) {
    outb(0xA1, 0xFF);   /* slave  : hepsi kapali */
    outb(0x21, 0xFC);   /* master : sadece IRQ0 (timer) ve IRQ1 (keyboard) */
}

bool is_exception_fatal(uint64_t vec) {
    switch (vec) {
    case 1:   /* Debug  */
    case 3:   /* Breakpoint */
    case 4:   /* Overflow */
    case 16:  /* x87 FPU */
        return false;
    default:
        return true;
    }
}

} /* namespace */

extern "C" void pic_remap(void) {
    outb(0x20, 0x11);
    io_wait();
    outb(0xA0, 0x11);
    io_wait();
    outb(0x21, 0x20);   /* PIC1 offset 0x20 */
    io_wait();
    outb(0xA1, 0x28);   /* PIC2 offset 0x28 */
    io_wait();
    outb(0x21, 0x04);
    io_wait();
    outb(0xA1, 0x02);
    io_wait();
    outb(0x21, 0x01);
    io_wait();
    outb(0xA1, 0x01);
    io_wait();
    mask_and_disable_all();
}

extern "C" void pic_send_eoi(uint8_t irq) {
    if (irq >= 8) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

extern "C" void isr_dispatch(uint64_t vec, uint64_t err) {
    if (vec < 32) {
        static const char* names[32] = {
            "Divide Error", "Debug", "NMI", "Breakpoint", "Overflow",
            "BOUND Range Exceeded", "Invalid Opcode", "Device Not Available",
            "Double Fault", "Coprocessor Segment Overrun", "Invalid TSS",
            "Segment Not Present", "Stack-Segment Fault", "General Protection Fault",
            "Page Fault", "Reserved", "x87 FPU Error", "Alignment Check",
            "Machine Check", "SIMD FPU Error", "Virtualization Exception",
            "Control Protection", "Reserved", "Reserved", "Reserved",
            "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
            "Security Exception", "Reserved"
        };
        kslog("EXCEPTION %llu (%s), err=0x%llx\n", vec,
              vec < 32 ? names[vec] : "?", err);
        kprintf("\n## EXCEPTION: %s (vec=%d err=0x%x)\n",
                vec < 32 ? names[vec] : "?", (int)vec, (uint32_t)err);
        if (is_exception_fatal(vec)) {
            kprintf("## system halted\n");
            cpu_cli();
            for (;;) cpu_hlt();
        }
        return;
    }

    if (vec >= 0x20 && vec < 0x30) {
        switch (vec) {
        case 0x20:
            timer_irq();
            pic_send_eoi(0);
            break;
        case 0x21:
            keyboard_irq();
            pic_send_eoi(1);
            break;
        case 0x27: case 0x2F:   /* spurious */
            break;
        default:
            kslog("..unknown IRQ %d\n", (int)(vec - 0x20));
            pic_send_eoi((uint8_t)(vec - 0x20));
            break;
        }
        return;
    }

    kslog("unhandled interrupt vec=%llu\n", vec);
}