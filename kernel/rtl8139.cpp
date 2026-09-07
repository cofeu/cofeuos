#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "pci.h"
#include "rtl8139.h"
#include "net.h"

int g_nic_irq = -1;

namespace {

constexpr     uint16_t OFF_TX_STATUS  = 0x10;  /* TSD0 */
constexpr     uint16_t OFF_TX_START   = 0x20;  /* TSAD0 */
constexpr     uint16_t OFF_RBSTART    = 0x30;
constexpr     uint16_t OFF_CR         = 0x37;
constexpr     uint16_t OFF_CAPR       = 0x38;
constexpr     uint16_t OFF_CBR        = 0x3A;
constexpr     uint16_t OFF_IMR        = 0x3C;
constexpr     uint16_t OFF_ISR        = 0x3E;
constexpr     uint16_t OFF_TCR        = 0x40;
constexpr     uint16_t OFF_RCR        = 0x44;
constexpr     uint16_t OFF_CONFIG1    = 0x52;
constexpr     uint16_t OFF_HLTCLK     = 0x5B;

constexpr uint32_t RX_BUF_SIZE = 0x10000;  /* 64KB (RCR RBS=11) */

uint16_t io = 0;
uint8_t  mac[6];
uint8_t* rx_buf = NULL;
uint32_t rx_cur = 0;
uint8_t* tx_buf = NULL;
bool     up = false;
uint8_t  tx_idx = 0;   /* QEMU donen Tx descriptor indeksi (0..3) */

void rx_overflow_recover(void) {
    uint16_t cbr = inw(io + OFF_CBR);
    kslog("rtl8139 RXOVW cbr=%u\n", (unsigned)cbr);
    rx_cur = cbr;                                   /* cihazin yazma konumuna hizala */
    outw(io + OFF_CAPR, (uint16_t)(cbr - 16));      /* overflow'u veriyle temizle */
}

void process_rx(void) {
    static uint8_t tmp[65536];
    uint16_t cbr = inw(io + OFF_CBR);
    while (rx_cur != cbr) {
        const uint8_t* d = rx_buf + rx_cur;
        uint32_t hdr;
        memcpy(&hdr, d, 4);
        uint16_t size   = (uint16_t)(hdr >> 16);    /* cerceve + 4 (CRC dahil) */
        uint16_t status = (uint16_t)(hdr & 0xFFFF);

        if ((status & 0x0001) == 0) {               /* ROK yok: henuz yazilmadi */
            kslog("rtl8139 ROK yok rx_cur=%u cbr=%u hdr=%08x (bekleniyor)\n",
                  (unsigned)rx_cur, (unsigned)cbr, (unsigned)hdr);
            break;                                  /* ringi SIFIRLAMA, tekrar dene */
        }

        if (rx_cur + 4u + size > RX_BUF_SIZE) {
            /* ring sonunu asan (sarmalanmis) paket: parca1 ucta, devam offset 0'da */
            uint32_t part1  = RX_BUF_SIZE - rx_cur - 4;         /* gercek verinin ucta kalan kismi */
            uint32_t remain = (uint32_t)size - 4u - part1;      /* CRC haric, ring basindaki kalan */
            if (part1 + remain > sizeof(tmp)) { rx_overflow_recover(); break; }
            memcpy(tmp, rx_buf + rx_cur + 4, part1);
            memcpy(tmp + part1, rx_buf, remain);                /* surekli kismi ring basinda */
            net_handle_eth(tmp, size - 4);
            rx_cur = (4u + remain + 3u) & (RX_BUF_SIZE - 4);    /* sonraki descriptor */
        } else {
            net_handle_eth(d + 4, size - 4);
            rx_cur = (rx_cur + 4u + size + 3u) & (RX_BUF_SIZE - 4);
        }

        cbr = inw(io + OFF_CBR);
    }
    outw(io + OFF_CAPR, (rx_cur >= 16) ? (uint16_t)(rx_cur - 16) : 0);
}

} /* namespace */

extern "C" bool rtl8139_init(uint16_t io_base, uint8_t irq, uint8_t bus, uint8_t slot, uint8_t func) {
    io = io_base;
    g_nic_irq = irq;

    pci_set_bus_master(bus, slot, func);       /* Komut bit2: DMA icin sart */

    for (int i = 0; i < 6; i++) mac[i] = inb(io + (uint16_t)i);

    outb(io + OFF_CONFIG1, 0x00);              /* power on */
    outl(io + OFF_HLTCLK, 0x52);               /* 'R': saat cikisini serbest (QEMU) */

    outb(io + OFF_CR, 0x10);                   /* soft reset */
    for (int i = 0; i < 1000 && (inb(io + OFF_CR) & 0x10); i++) io_wait();

    rx_buf = (uint8_t*)pmm_alloc_range(32);    /* 128KB; 64K hizaya yuvarla (gercek HW) */
    if (!rx_buf) { kslog("rtl8139: rx tampon ayrilamadi\n"); return false; }
    rx_buf = (uint8_t*)(((uintptr_t)rx_buf + 0xFFFFu) & ~(uintptr_t)0xFFFFu);
    memset(rx_buf, 0, RX_BUF_SIZE);
    rx_cur = 0;

    tx_buf = (uint8_t*)pmm_alloc_frame();
    if (!tx_buf) return false;
    memset(tx_buf, 0, 4096);

    outl(io + OFF_RBSTART, (uint32_t)(uintptr_t)rx_buf);

    outw(io + OFF_IMR, 0x0005);                /* ROK + TOK */
    outl(io + OFF_TCR, 0);
    outl(io + OFF_RCR, 0x0000180Fu);           /* 64K ring (RBS=11) + promiscuous + wrap */

    outb(io + OFF_CR, 0x0C);                   /* TE + RE */
    outw(io + OFF_ISR, 0xFFFF);                /* eski kesmeleri temizle */

    up = true;
    kprintf("rtl8139: MAC %02x:%02x:%02x:%02x:%02x:%02x irq=%u io=0x%x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], irq, io);
    kslog("rtl8139 pci up=%d irq=%d io=0x%x\n", up, irq, io);
    return true;
}

extern "C" void rtl8139_send(const void* data, uint16_t len) {
    if (!up) return;
    if (len > 1514) len = 1514;
    memcpy(tx_buf, data, len);

    outl(io + OFF_TX_START + tx_idx * 4u, (uint32_t)(uintptr_t)tx_buf);  /* TSADn */
    outl(io + OFF_TX_STATUS + tx_idx * 4u, (uint32_t)(len & 0x1FFF));    /* TSDn  */

    for (int i = 0; i < 500000; i++) {           /* TOK (bit15) gelene kadar bekle */
        if (inl(io + OFF_TX_STATUS + tx_idx * 4u) & 0x8000u) break;
        io_wait();
    }
    tx_idx = (uint8_t)((tx_idx + 1) & 3);
}

extern "C" void rtl8139_poll(void) {
    if (!up) return;
    uint16_t isr = inw(io + OFF_ISR);
    if (!(isr & 0x0001u)) return;
    outw(io + OFF_ISR, isr);
    if (isr & 0x0010u) rx_overflow_recover();      /* RXOVW */
    if (isr & 0x0001u) process_rx();              /* ROK */
}

extern "C" void rtl8139_irq(void) {
    if (!up) return;
    uint16_t isr = inw(io + OFF_ISR);
    if (!isr) return;
    outw(io + OFF_ISR, isr);                     /* hepsini ack'le */
    if (isr & 0x0010u) rx_overflow_recover();    /* RXOVW: ringi sifirlama, hizala */
    if (isr & 0x0001u) process_rx();             /* ROK */
}

extern "C" void rtl8139_get_mac(uint8_t out[6]) {
    for (int i = 0; i < 6; i++) out[i] = mac[i];
}

extern "C" bool rtl8139_active(void) { return up; }