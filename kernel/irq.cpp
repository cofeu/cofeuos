#include "kernel.h"
#include "x86.h"
#include "sched.h"
#include "nic.h"
#include "net.h"

namespace {

void mask_and_disable_all(void) {
    outb(0xA1, 0xE1);   /* slave  : IRQ9-12 acik (ag kartlari, herhangi bir hat) */
    outb(0x21, 0xFC);   /* master : IRQ0 (timer) ve IRQ1 (keyboard), kasit */
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

uint64_t exception_crash(uint64_t vec, uint64_t err, uint64_t ctx) {
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
    uint64_t* r = (uint64_t*)ctx;
    uint64_t uip = ((r[18] & 3) == 3) ? r[17] : 0;   /* cs ve rip (user) */
    uint64_t cr2 = 0;
    if (vec == 14) asm volatile("mov %%cr2, %0" : "=r"(cr2));
    kslog("EXCEPTION %llu (%s), err=0x%llx uip=0x%llx cr2=0x%llx cs=0x%llx rip=0x%llx fl=0x%llx\n",
          vec, vec < 32 ? names[vec] : "?", err, uip, cr2, r[18], r[17], r[19]);
    kprintf("\n## EXCEPTION: %s (vec=%d err=0x%x%s)\n",
            vec < 32 ? names[vec] : "?", (int)vec, (uint32_t)err,
            uip ? " [user]" : "");
    if (vec == 14) kprintf("## cr2=0x%x\n", (uint32_t)cr2);
    if (!is_exception_fatal(vec)) return ctx;
    kprintf("## system halted\n");
    cpu_cli();
    for (;;) cpu_hlt();

    return ctx;
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

extern "C" uint64_t isr_dispatch(uint64_t vec, uint64_t err, uint64_t ctx) {
    if (vec < 32) {
        /* kullanici modunda page fault: sureci oldur, sistemi degil (izolasyon) */
        if (vec == 14) {
            uint64_t* r = (uint64_t*)ctx;
            if ((r[18] & 3) == 3) return sched_userpf_kill(ctx);   /* [18] = cs */
        }
        return exception_crash(vec, err, ctx);
    }

    if (vec == 0x80)
        return syscall_handle(ctx);

    if (vec >= 0x20 && vec < 0x30) {
        switch (vec) {
        case 0x20:
            timer_irq();
            nic_poll_all();          /* ag paketleri zamanlayiciyla da islenir */
            net_tcp_poll_all();      /* TCP retrans/RTO/FIN teardown arka planda */
            pic_send_eoi(0);
            return sched_tick(ctx);
        case 0x21:
            keyboard_irq();
            pic_send_eoi(1);
            break;
        case 0x29: case 0x2A: case 0x2B: case 0x2C:   /* IRQ9-12: ag kartlari */
            nic_irq((int)(vec - 0x20));
            pic_send_eoi((uint8_t)(vec - 0x20));
            break;
        case 0x27: case 0x2F:   /* spurious */
            break;
        default:
            kslog("..unknown IRQ %d\n", (int)(vec - 0x20));
            pic_send_eoi((uint8_t)(vec - 0x20));
            break;
        }
        return ctx;
    }

    kslog("unhandled interrupt vec=%llu\n", vec);
    return ctx;
}