#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "sched.h"
#include "rtc.h"
#include "pci.h"
#include "nic.h"
#include "net.h"

/* Uygulamalar (/sys/'*.cexe') derleme aninda tools/mkfs.py ile disk.img'ye
   yazilir; kernel.bin'de ELF gommek boot 127-sektor limitini asardi. */

extern "C" void kernel_main(void) {
    serial_init();
    kslog("cofeuos: kernel entry\n");
    vga_init();

    kslog("cofeuos 0.1 boot\n");
    kprintf("cofeuos 0.1.0 - x86_64 boot ediliyor...\n");

    gdt_init();
    idt_init();
    pic_remap();
    timer_init();
    rtc_init();

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
        if (mnt) {
            fs::selftest();
        }
    }

    pci_scan();
    int nics = nic_probe();
    const NicDevice* nic = nic_current();
    if (nics > 0 && nic) {
        kprintf("net : aktif NIC = %s\n", nic->name);
        {
            uint8_t mac[6];
            memcpy(mac, nic->mac, 6);
            net_init(mac, 0, 0, 0);                  /* anahtar: MAC; IP DHCP'den */
            if (net_dhcp()) {
                uint32_t ip = net_get_ip(), gw = net_get_gw();
                kprintf("net : %s DHCP tamam (%u.%u.%u.%u, kapidan %u.%u.%u.%u)\n",
                        nic->name,
                        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                        (gw >> 24) & 0xFF, (gw >> 16) & 0xFF, (gw >> 8) & 0xFF, gw & 0xFF);
            } else {
                net_init(mac, 0x0A00020F, 0xFFFFFF00, 0x0A000202);
                kprintf("net : %s DHCP zaman asimi, sabit 10.0.2.15/24 (kapidan 10.0.2.2)\n",
                        nic->name);
            }
        }
    } else {
        kprintf("net : ag karti bulunamadi\n");
    }

    keyboard_init();

    sched_init();
    int p1 = sched_spawn("mercury");
    int p2 = sched_spawn("venus");
    int p3 = sched_spawn("earth");
    int p4 = sched_spawn("byn");
    kprintf("sched: islemler baslatildi (pid %04X, %04X, %04X, %04X)\n",
            p1 & 0xFFFF, p2 & 0xFFFF, p3 & 0xFFFF, p4 & 0xFFFF);
    kslog("sched spawns %d/%d/%d/%d\n", p1, p2, p3, p4);
    sched_go();                       /* spawn'lardan sonra kullaniciya izin ver */

    shell_run();

    for (;;) cpu_hlt();
}