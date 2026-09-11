#include "kernel.h"
#include "x86.h"
#include "pci.h"
#include "pmm.h"
#include "nic.h"
#include "mmio.h"
#include "net.h"

/* Intel 82540EM e1000 (QEMU). Kayitlar MMIO (BAR0), legacy 16-bayt
   descriptor bicimi kullanilir.
   - RX: 16 tampon + 16'lik ring; RAR0(AV) unicast, BAM broadcast,
     MPE multicast kabulu (QEMU filtresi RAL/RAH + MTA kullanir).
     CRC (dalga SECRC'siz dahildir) yazilimda -4 ile ayrilir.
   - TX: 8 slot'luk ring, her cerceve tek descriptor (EOP|IFCS|RS),
     senkron (DD beklenir). */

namespace {

/* ---- kayit ofsetleri ---- */
constexpr uint32_t R_CTRL    = 0x0000;
constexpr uint32_t R_STATUS  = 0x0008;
constexpr uint32_t R_EEPROM  = 0x0014;
constexpr uint32_t R_ICR     = 0x00C0;
constexpr uint32_t R_IMS     = 0x00D0;
constexpr uint32_t R_IMC     = 0x00D8;
constexpr uint32_t R_RCTL    = 0x0100;
constexpr uint32_t R_TCTL    = 0x0400;
constexpr uint32_t R_RDBAL   = 0x2800;
constexpr uint32_t R_RDBAH   = 0x2804;
constexpr uint32_t R_RDLEN   = 0x2808;
constexpr uint32_t R_RDH     = 0x2810;
constexpr uint32_t R_RDT     = 0x2818;
constexpr uint32_t R_TDBAL   = 0x3800;
constexpr uint32_t R_TDBAH   = 0x3804;
constexpr uint32_t R_TDLEN   = 0x3808;
constexpr uint32_t R_TDH     = 0x3810;
constexpr uint32_t R_TDT     = 0x3818;
constexpr uint32_t R_MTA     = 0x5200;
constexpr uint32_t R_RAL     = 0x5400;
constexpr uint32_t R_RAH     = 0x5404;

constexpr uint32_t CTRL_RST  = 0x04000000;
constexpr uint32_t CTRL_SLU  = 0x00000040;
constexpr uint32_t STATUS_LU = 0x00000002;      /* Link Up */

constexpr uint32_t RCTL_EN   = 0x00000002;
constexpr uint32_t RCTL_MPE  = 0x00000010;      /* multicast promiscuous */
constexpr uint32_t RCTL_LPE  = 0x00000020;      /* long packet enable */
constexpr uint32_t RCTL_BAM  = 0x00008000;      /* broadcast enable */

constexpr uint32_t TCTL_EN   = 0x00000002;
constexpr uint32_t TCTL_PSP  = 0x00000008;
/* CT(alisen) = 15<<4, COLD = 63<<12 (Linux e1000 degerleri) */
constexpr uint32_t TCTL_CT   = 0x000000F0;
constexpr uint32_t TCTL_COLD = 0x0003F000;

constexpr uint8_t  RXS_DD    = 0x01;   /* descriptor done */
constexpr uint8_t  RXS_EOP   = 0x02;   /* end of packet */
constexpr uint8_t  RXE_CE    = 0x01;   /* CRC error */
constexpr uint8_t  RXE_SEQ   = 0x04;   /* sequence error */
constexpr uint8_t  RXE_RXE   = 0x80;   /* rx data error */

constexpr uint8_t  TXC_EOP   = 0x01;
constexpr uint8_t  TXC_IFCS  = 0x02;   /* insert FCS (eski term: append CRC) */
constexpr uint8_t  TXC_RS    = 0x08;   /* report status (DD yazimi) */

enum { RX_SLOTS = 16, RX_BUF = 2048 };
enum { TX_SLOTS = 8 };

struct RxDesc {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t  status;
    uint8_t  errors;
    uint16_t special;
} __attribute__((packed));

struct TxDesc {
    uint64_t addr;
    uint16_t length;
    uint8_t  cso;
    uint8_t  cmd;
    uint8_t  status;
    uint8_t  css;
    uint16_t special;
} __attribute__((packed));

volatile uint32_t* mmio = NULL;
uint8_t   mac[6];
bool      up = false;

/* RX: 16 tampon (2048 bayt) + 16'lik descriptor halkasi */
uint8_t*        rx_bufs[RX_SLOTS];
volatile RxDesc* rx_ring = NULL;
uint32_t         rx_next = 0;

/* TX: 8 slot, her birine kendi tamponu (senkron gonderim). */
volatile TxDesc* tx_ring = NULL;
uint8_t*         tx_bufs[TX_SLOTS];
uint32_t         tx_next = 0;

/* NIC sayaclari (ifconfig NIC ist satiri) */
uint64_t st_rx_ok   = 0;
uint64_t st_rx_err  = 0;
uint64_t st_rx_drop = 0;
uint64_t st_rx_ovw  = 0;
uint64_t st_tx_ok   = 0;
uint64_t st_tx_err  = 0;
uint64_t st_tx_drop = 0;

uint32_t reg_read(uint32_t off)   { return mmio[off / 4]; }
void     reg_write(uint32_t off, uint32_t v) { mmio[off / 4] = v; }

uint16_t eeprom_read(int reg) {
    reg_write(R_EEPROM, (uint32_t)((reg << 8) | 0x1));
    for (int i = 0; i < 1000; i++) {
        uint32_t v = reg_read(R_EEPROM);
        if (v & 0x10) return (uint16_t)(v >> 16);
    }
    return 0;
}

/* RX: DD'li slotlari tuket. Tur atlama: EOP olmayan (coklu-descriptor)
   cerceveler, hatali (CE/SEQ/RXE) cerceveler dusurulur. */
static void rx_process(void) {
    bool skipping = false;
    while (rx_ring[rx_next].status & RXS_DD) {
        volatile RxDesc& d = rx_ring[rx_next];
        bool eop = (d.status & RXS_EOP) != 0;

        if (skipping) {
            if (eop) skipping = false;
            st_rx_drop++;
        } else if (!eop) {
            skipping = true;
            st_rx_drop++;
        } else if (d.errors & (RXE_CE | RXE_SEQ | RXE_RXE)) {
            st_rx_err++;
        } else {
            uint16_t len = d.length;
            if (len > 4) len = (uint16_t)(len - 4);       /* son 4 = CRC */
            if (len > 1514) len = 1514;
            net_handle_eth(rx_bufs[rx_next], len);
            st_rx_ok++;
        }
        d.status = 0;
        d.errors = 0;
        reg_write(R_RDT, rx_next);         /* tamponu yeniden ver */
        rx_next = (rx_next + 1) % RX_SLOTS;
    }
}

/* Busy-wait ile senkron TX: slot kullanilabilir olana kadar bekle,
   gonder, DD gorunene kadar bekle. */
static void e1000_send(const uint8_t* frame, uint16_t len) {
    if (!up) { st_tx_drop++; return; }
    if (len > 1514) len = 1514;

    const uint32_t i = tx_next;
    for (int w = 0; w < 500000 && !(tx_ring[i].status & RXS_DD); w++) { }
    tx_ring[i].status = 0;

    volatile TxDesc& t = tx_ring[i];
    memcpy(tx_bufs[i], frame, len);
    t.addr   = (uint64_t)(uintptr_t)tx_bufs[i];
    t.length = len;
    t.cso    = 0;
    t.cmd    = TXC_EOP | TXC_IFCS | TXC_RS;
    t.css    = 0;
    t.special = 0;
    reg_write(R_TDT, (i + 1) % TX_SLOTS);

    for (int w = 0; w < 500000 && !(tx_ring[i].status & RXS_DD); w++) { }
    if (tx_ring[i].status & RXS_DD) st_tx_ok++;
    else                            st_tx_err++;
    tx_ring[i].status = 0;
    tx_next = (i + 1) % TX_SLOTS;
}

static void e1000_poll(void) {
    if (!up) return;
    reg_read(R_ICR);                              /* kesme onayini temizle */
    rx_process();
}

static void e1000_irq(void) { e1000_poll(); }

static bool e1000_active(void) { return up; }

static bool e1000_link(void) { return up && (reg_read(R_STATUS) & STATUS_LU) != 0; }

static void e1000_stats(NicStats* out) {
    out->rx_ok   = st_rx_ok;
    out->rx_err  = st_rx_err;
    out->rx_drop = st_rx_drop;
    out->rx_ovw  = st_rx_ovw;
    out->tx_ok   = st_tx_ok;
    out->tx_err  = st_tx_err;
    out->tx_drop = st_tx_drop;
}

static const NicOps e1000_ops = { e1000_send, e1000_poll, e1000_irq, e1000_active, e1000_link, e1000_stats };

/* multicast adresini MTA'ya isle (rasilan 12-bit dolu; MO=0 -> [47:36]).
   Gercek 82540 ile QEMU ayni kurali kullanir (e1000x_rx_group_filter). */
static void mta_add(const uint8_t* a) {
    uint32_t h = (((uint32_t)a[5] << 4) | ((uint32_t)a[4] >> 4)) & 0xFFFu;
    uint32_t off = R_MTA + 4 * (h >> 5);
    reg_write(off, reg_read(off) | (1u << (h & 0x1Fu)));
}

extern "C" bool e1000_nic_probe(const PCIDevice* pci, NicDevice* out) {
    if (up) return false;
    if (pci->vendor_id != 0x8086 || pci->device_id != 0x100E) return false;

    uint32_t bar0 = pci->bar0;
    if (bar0 & 1) return false;                       /* yalnizca memory BAR desteklenir */
    uint32_t base = bar0 & 0xFFFFFFF0u;

    if (!mmio_map_device(base, 128 * 1024)) { kprintf("e1000: MMIO haritalanamadi\n"); return false; }
    mmio = (volatile uint32_t*)(uintptr_t)base;
    pci_set_bus_master(pci->bus, pci->slot, pci->func);

    /* sifirla */
    reg_write(R_CTRL, reg_read(R_CTRL) | CTRL_RST);
    for (int i = 0; i < 1000; i++) io_wait();
    reg_write(R_CTRL, 0);
    for (int i = 0; i < 1000; i++) io_wait();

    /* baglanti kur */
    reg_write(R_CTRL, CTRL_SLU | 0x20);       /* SLU + ASDE (otomatik hiz) */

    /* MAC: once EEPROM'dan, sonra RA kayitlarindan */
    uint16_t ep0 = eeprom_read(0), ep1 = eeprom_read(1), ep2 = eeprom_read(2);
    if (ep0 && (ep0 != 0xFFFF)) {
        mac[0] = (uint8_t)(ep0 & 0xFF); mac[1] = (uint8_t)(ep0 >> 8);
        mac[2] = (uint8_t)(ep1 & 0xFF); mac[3] = (uint8_t)(ep1 >> 8);
        mac[4] = (uint8_t)(ep2 & 0xFF); mac[5] = (uint8_t)(ep2 >> 8);
    } else {
        uint32_t ral = reg_read(R_RAL), rah = reg_read(R_RAH);
        mac[0] = (uint8_t)(ral & 0xFF); mac[1] = (uint8_t)((ral >> 8) & 0xFF);
        mac[2] = (uint8_t)((ral >> 16) & 0xFF); mac[3] = (uint8_t)((ral >> 24) & 0xFF);
        mac[4] = (uint8_t)(rah & 0xFF); mac[5] = (uint8_t)((rah >> 8) & 0xFF);
    }

    /* RX filtre: RAR0'da kendi MAC'imiz (AV). QEMU yalnizca eslesen
       unicast'i kabul eder; bu olmadan yonlendirilmis paketler dusuyordu. */
    reg_write(R_RAL, (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) |
                     ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24));
    reg_write(R_RAH, (uint32_t)mac[4] | ((uint32_t)mac[5] << 8) | 0x80000000u);

    /* IPv6 all-nodes (33:33:00:00:00:01) MTA'ya; MPE diger multicastlari. */
    static const uint8_t mcast_allip6[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };
    mta_add(mcast_allip6);

    /* RX ring + tamponlar */
    rx_ring = (volatile RxDesc*)pmm_alloc_frame();
    if (!rx_ring) return false;
    memset((void*)rx_ring, 0, 4096);
    for (int i = 0; i < RX_SLOTS; i++) {
        rx_bufs[i] = (uint8_t*)pmm_alloc_frame();
        if (!rx_bufs[i]) return false;
        memset(rx_bufs[i], 0, 4096);
        rx_ring[i].addr = (uint64_t)(uintptr_t)rx_bufs[i];
    }
    reg_write(R_RDBAL, (uint32_t)(uintptr_t)rx_ring);
    reg_write(R_RDBAH, 0);
    reg_write(R_RDLEN, RX_SLOTS * 16);
    reg_write(R_RDH, 0);
    reg_write(R_RDT, RX_SLOTS - 1);
    rx_next = 0;

    /* TX ring + tamponlar */
    tx_ring = (volatile TxDesc*)pmm_alloc_frame();
    if (!tx_ring) return false;
    memset((void*)tx_ring, 0, 4096);
    tx_next = 0;
    for (int i = 0; i < TX_SLOTS; i++) {
        tx_bufs[i] = (uint8_t*)pmm_alloc_frame();
        if (!tx_bufs[i]) return false;
    }
    reg_write(R_TDBAL, (uint32_t)(uintptr_t)tx_ring);
    reg_write(R_TDBAH, 0);
    reg_write(R_TDLEN, TX_SLOTS * 16);
    reg_write(R_TDH, 0);
    reg_write(R_TDT, 0);

    /* etkinlestir */
    reg_write(R_RCTL, RCTL_EN | RCTL_BAM | RCTL_MPE | RCTL_LPE);
    reg_write(R_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
    reg_read(R_ICR);
    reg_write(R_IMS, 0x1F6DC);                              /* RX/TX kesme isleri */

    up = true;
    out->name = "e1000";
    out->kind = NIC_WIRED;
    out->irq  = pci->irq;
    out->up   = true;
    memcpy(out->mac, mac, 6);
    out->ops  = &e1000_ops;

    kprintf("e1000: MAC %02x:%02x:%02x:%02x:%02x:%02x irq=%d bar0=0x%x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pci->irq, base);
    kslog("e1000 up irq=%d base=0x%x\n", pci->irq, base);
    return true;
}

} /* namespace */