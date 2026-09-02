#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "sched.h"

extern "C" void kernel_main(void) {
    vga_init();
    serial_init();

    kslog("cofeuos 0.1 boot\n");
    kprintf("cofeuos 0.1.0 - x86_64 boot ediliyor...\n");

    gdt_init();
    idt_init();
    pic_remap();
    timer_init();

    pmm_init();
    kmalloc_init();

    kprintf("mem : %lu MB toplam, %lu KB yonetilen, %lu serbest frame, heap %lu/%lu KB\n",
            pmm_total_kb() / 1024u, pmm_managed_kb(),
            (unsigned long)pmm_free_frames(),
            (unsigned long)(kmem_used() / 1024u), (unsigned long)(kmem_capacity() / 1024u));
    kslog("mem total=%luKB managed=%luKB heap_cap=%luKB\n",
          pmm_total_kb(), pmm_managed_kb(), (unsigned long)(kmem_capacity() / 1024u));

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

    sched_init();
    int p1 = sched_spawn("mercury", 'M', 200, 5);
    int p2 = sched_spawn("venus",   'V', 320, 4);
    int p3 = sched_spawn("earth",   'E', 480, 3);
    int p4 = sched_spawn("byn",     'B',   60, 3);
    kprintf("sched: demo islemler (pid %04X, %04X, %04X, %04X)\n",
            p1 & 0xFFFF, p2 & 0xFFFF, p3 & 0xFFFF, p4 & 0xFFFF);
    kslog("sched spawns %d/%d/%d/%d\n", p1, p2, p3, p4);

    shell_run();

    for (;;) cpu_hlt();
}