#include "kernel.h"
#include "x86.h"

extern "C" void kernel_main(void) {
    vga_init();
    serial_init();

    kslog("cofeuos 0.1 boot\n");
    kprintf("cofeuos 0.1.0 - x86_64 boot ediliyor...\n");

    gdt_init();
    idt_init();
    pic_remap();
    timer_init();

    cpu_sti();

    bool ata = ata_init();
    bool ident = ata_identify();
    kprintf("ata: %s (%s)\n", ata ? "var" : "yok", ident ? "kimlik alindi" : "tanimsiz");
    kslog("ata present=%d ident=%d\n", ata ? 1 : 0, ident ? 1 : 0);

    if (ata) {
        bool mnt = fs::mount();
        kprintf("fs : %s\n", mnt ? "cofeufs bagli" : "BAGLANAMADI");
        kslog("fs mount=%d\n", mnt ? 1 : 0);
        if (mnt) fs::selftest();
    }

    keyboard_init();

    shell_run();

    for (;;) cpu_hlt();
}