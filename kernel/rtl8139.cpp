#include "kernel.h"
#include "x86.h"
#include "pmm.h"
#include "pci.h"
#include "rtl8139.h"
#include "nic.h"
#include "net.h"

/* Realtek RTL8139 (classic) surucusu. Referans: Linux 8139too.c + OSDev.
   Port I/O tabanli; 64KB yesil (wrap) RX ring + 4 descriptor TX ring. */

int g_nic_irq = -1;

namespace {

/* ---- register ofsetleri (8139too.c ile birebir) ---- */
constexpr uint16_t R_MAC0      = 0x00;   /* Ethernet MAC (IDR) */
constexpr uint16_t R_MAR0      = 0x08;   /* multicast filtre (MAR0-3, 32 bit) */
constexpr uint16_t R_TXSTATUS  = 0x10;   /* TSD0 */
constexpr uint16_t R_TXSTART   = 0x20;   /* TSAD0 */
constexpr uint16_t R_RXSTART   = 0x30;   /* RxBuf */
constexpr uint16_t R_CMD       = 0x37;   /* ChipCmd */
constexpr uint16_t R_CAPR      = 0x38;   /* RxBufPtr */
constexpr uint16_t R_CBR       = 0x3A;   /* RxBufAddr */
constexpr uint16_t R_IMR       = 0x3C;
constexpr uint16_t R_ISR       = 0x3E;
constexpr uint16_t R_TCR       = 0x40;   /* TxConfig */
constexpr uint16_t R_RCR       = 0x44;   /* RxConfig */
constexpr uint16_t R_RXMISSED  = 0x4C;
constexpr uint16_t R_CFG9346   = 0x50;
constexpr uint16_t R_CONFIG1   = 0x52;
constexpr uint16_t R_CONFIG3   = 0x59;
constexpr uint16_t R_HLTCLK    = 0x5B;
constexpr uint16_t R_MULTIINTR = 0x5C;
constexpr uint16_t R_BMCR      = 0x62;   /* MII reg0 (BasicModeCtrl) */
constexpr uint16_t R_BMSR      = 0x64;   /* MII reg1 (BasicModeStatus) */
constexpr uint16_t R_ANAR      = 0x66;   /* MII reg4 (NWayAdvert) */
constexpr uint16_t R_ANLPAR    = 0x68;   /* MII reg5 (NWayLPAR) */
constexpr uint16_t R_ANER      = 0x6A;   /* MII reg6 (NWayExpansion) */

/* ---- ChipCmd ---- */
constexpr uint8_t  CMD_RESET   = 0x10;
constexpr uint8_t  CMD_RX_EN   = 0x08;
constexpr uint8_t  CMD_TX_EN   = 0x04;

/* ---- IntrStatus / IntrMask ---- */
constexpr uint16_t ISR_PCIERR  = 0x8000;
constexpr uint16_t ISR_PCSTO   = 0x4000;
constexpr uint16_t ISR_RXFOV   = 0x40;   /* RxFIFOOver */
constexpr uint16_t ISR_RXUN    = 0x20;   /* RxUnderrun */
constexpr uint16_t ISR_RXOVW   = 0x10;   /* RxOverflow */
constexpr uint16_t ISR_TXERR   = 0x08;
constexpr uint16_t ISR_TOK     = 0x04;
constexpr uint16_t ISR_RXERR   = 0x02;
constexpr uint16_t ISR_ROK     = 0x01;

constexpr uint16_t IMR_ALL = ISR_PCIERR | ISR_PCSTO | ISR_RXFOV |
                             ISR_RXUN | ISR_RXOVW | ISR_TXERR |
                             ISR_TOK | ISR_RXERR | ISR_ROK;   /* = 0xC07F */

/* ---- TxStatus (TSDn) bitleri ---- */
constexpr uint32_t TSD_HOST    = 0x2000;   /* TxHostOwns (abort sonrasi) */
constexpr uint32_t TSD_UNDRUN  = 0x4000;
constexpr uint32_t TSD_TOK     = 0x8000;   /* TxStatOK */
constexpr uint32_t TSD_OWIN    = 0x20000000;
constexpr uint32_t TSD_ABORT   = 0x40000000;
constexpr uint32_t TSD_CLOST   = 0x80000000;
constexpr uint32_t TSD_DONE    = TSD_TOK | TSD_UNDRUN | TSD_ABORT;
constexpr uint32_t TSD_FIFO    = (256u << 11) & 0x003F0000u;  /* esik 256B */

/* ---- RxStatus (RX basligi) bitleri ---- */
constexpr uint32_t RXT_MCAST   = 0x8000;
constexpr uint32_t RXT_PHYS    = 0x4000;
constexpr uint32_t RXT_BCAST   = 0x2000;
constexpr uint32_t RXT_BADSYM  = 0x0020;
constexpr uint32_t RXT_RUNT    = 0x0010;
constexpr uint32_t RXT_LONG    = 0x0008;
constexpr uint32_t RXT_CRCERR  = 0x0004;
constexpr uint32_t RXT_BADAL   = 0x0002;
constexpr uint32_t RXT_OK      = 0x0001;
constexpr uint32_t RXT_ERRORS  = RXT_BADSYM | RXT_RUNT | RXT_LONG |
                                RXT_CRCERR | RXT_BADAL;

/* ---- RxConfig (RCR) ---- */
constexpr uint32_t RCR_ACCERR  = 0x20;    /* AcceptErr */
constexpr uint32_t RCR_ACCRUN  = 0x10;    /* AcceptRunt */
constexpr uint32_t RCR_ACBCST  = 0x08;    /* AcceptBroadcast */
constexpr uint32_t RCR_ACMULT  = 0x04;    /* AcceptMulticast */
constexpr uint32_t RCR_ACPHYS  = 0x02;    /* AcceptMyPhys */
constexpr uint32_t RCR_ACALL   = 0x01;    /* AcceptAllPhys */
constexpr uint32_t RCR_RBS64K  = 0x1800;  /* RxCfgRcv64K (wrap zorunlu) */
constexpr uint32_t RCR_FIFO    = 7u << 13;   /* RxCfgFIFONone? esik 7 */
constexpr uint32_t RCR_DMA     = 6u << 8;    /* RxCfgDMAUnlimited */
constexpr uint32_t RCR_BASE    = RCR_RBS64K | RCR_FIFO | RCR_DMA;

/* ---- TxConfig (TCR) ---- */
constexpr uint32_t TCR_IFG96   = 3u << 24;  /* IEEE uyumlu tek IFG */
constexpr uint32_t TCR_DMA     = 6u << 8;   /* TX_DMA_BURST=6 (1024B) */
constexpr uint32_t TCR_RETRY   = 8u << 4;   /* TX_RETRY=8 */
constexpr uint32_t TCR_CLEARABT= 0x01;

/* ---- Cfg9346 / 93C46 ---- */
constexpr uint8_t  CFG_UNLOCK  = 0xC0;
constexpr uint8_t  CFG_LOCK    = 0x00;
constexpr uint8_t  EE_SHIFT_CLK = 0x04;
constexpr uint8_t  EE_CS        = 0x08;
constexpr uint8_t  EE_DATA_WRITE= 0x02;
constexpr uint8_t  EE_DATA_READ = 0x01;
constexpr uint8_t  EE_ENB       = 0x80 | EE_CS;
constexpr uint16_t EE_READ_CMD  = 6;    /* 93C46 READ opcode oncesi start biti */
constexpr uint16_t EE_MAGIC     = 0x8129;

/* ---- Config1/3 ---- */
constexpr uint8_t  CFG1_SLEEP  = 0x02;
constexpr uint8_t  CFG1_PWRDN  = 0x01;
constexpr uint8_t  CFG3_MAGIC  = 0x20;  /* wake-up magic packet tarama */

constexpr uint32_t RX_BUF_SIZE = 0x10000;   /* 64K */
constexpr int      NUM_TX      = 4;

uint16_t io      = 0;
uint8_t  mac[6];
uint8_t* rx_buf  = NULL;
uint32_t rx_cur  = 0;
uint8_t* tx_bufs[NUM_TX];
uint32_t cur_tx  = 0;      /* doldurulacak sonraki slot */
uint32_t dirty_tx = 0;     /* toplanacak (reap) sonraki slot */
bool     up      = false;
bool     promisc = false;

/* hata/istatistik (M1.2 / M1.4) */
uint64_t st_rx_ok, st_rx_err, st_rx_drop, st_rx_ovw;
uint64_t st_tx_ok, st_tx_err, st_tx_drop;

/* multicast filtre listesi (M1.3): MAR hash hesabi icin */
enum { MCAST_MAX = 8 };
uint8_t  mcast[MCAST_MAX][6];
int      mcast_n = 0;

/* ================= 93C46 serial EEPROM (M1.1) ================= */

static void eeprom_delay(void) { (void)inb(io + R_CFG9346); }

static uint16_t eeprom_read_word(int location, int addr_len) {
    uint32_t read_cmd = (uint32_t)location | ((uint32_t)EE_READ_CMD << addr_len);

    /* CS'yi dusur, sonra yukselt (start garantisi) */
    outb(io + R_CFG9346, EE_ENB & ~EE_CS);
    outb(io + R_CFG9346, EE_ENB);
    eeprom_delay();

    /* komut bitlerini MSB-oncesi gonder: start(1) + opcode(10) + adres */
    for (int i = 4 + addr_len; i >= 0; i--) {
        uint8_t dv = (read_cmd & (1u << i)) ? EE_DATA_WRITE : 0;
        outb(io + R_CFG9346, EE_ENB | dv);
        eeprom_delay();
        outb(io + R_CFG9346, EE_ENB | dv | EE_SHIFT_CLK);
        eeprom_delay();
    }
    outb(io + R_CFG9346, EE_ENB);
    eeprom_delay();

    /* 16 veri bitini DO'dan oku */
    uint16_t ret = 0;
    for (int i = 16; i > 0; i--) {
        outb(io + R_CFG9346, EE_ENB | EE_SHIFT_CLK);
        eeprom_delay();
        ret = (uint16_t)((ret << 1) |
              ((inb(io + R_CFG9346) & EE_DATA_READ) ? 1 : 0));
        outb(io + R_CFG9346, EE_ENB);
        eeprom_delay();
    }

    outb(io + R_CFG9346, 0);       /* erisimi sonlandir */
    eeprom_delay();
    return ret;
}

static bool mac_valid(const uint8_t m[6]) {
    bool zero = true, ff = true;
    for (int i = 0; i < 6; i++) {
        if (m[i] != 0)    zero = false;
        if (m[i] != 0xFF) ff = false;
    }
    return !zero && !ff && !(m[0] & 1);   /* multicast/yerel bit temiz */
}

static bool mac_from_eeprom(void) {
    uint16_t w0 = eeprom_read_word(0, 8);
    int addr_len = (w0 == EE_MAGIC) ? 8 : 6;

    /* Linux: MAC sozcuk 7,8,9 */
    uint16_t w[3];
    for (int i = 0; i < 3; i++) w[i] = eeprom_read_word(7 + i, addr_len);
    if ((w[0] & w[1] & w[2]) == 0xFFFF) return false;   /* tumu bos */

    uint8_t m[6] = {
        (uint8_t)(w[0] & 0xFF), (uint8_t)(w[0] >> 8),
        (uint8_t)(w[1] & 0xFF), (uint8_t)(w[1] >> 8),
        (uint8_t)(w[2] & 0xFF), (uint8_t)(w[2] >> 8),
    };
    if (!mac_valid(m)) return false;
    memcpy(mac, m, 6);
    return true;
}

/* ================= chipset tespiti (M1.5) ================= */

/* HW_REVID bit ornekleri (8139too rtl_chip_info tablosu). */
static int chipset_version(void) {
    return (int)(inl(io + R_TCR) & 0x7CC00000u);
}
static bool has_hltclk(void) {
    /* RTL-8139 .. 8139A rev G: HltClk var; 8139B ve sonrasi: yok */
    return (chipset_version() & 0x08000000u) == 0;
}
static bool is_8139b_plus(void) {
    return (chipset_version() & 0x08000000u) != 0;
}

/* ================= MII / PHY (M1.6) ================= */

static const uint8_t mii_map[8] = {
    R_BMCR, R_BMSR, 0, 0, R_ANAR, R_ANLPAR, R_ANER, 0,
};

static uint16_t mii_read(uint8_t reg) {
    if (reg >= sizeof(mii_map)) return 0xFFFF;
    uint8_t off = mii_map[reg];
    if (!off) return 0xFFFF;
    return inw(io + off);
}

static bool link_now(void) {
    uint16_t bmsr = mii_read(1);        /* MII_BMSR */
    if (bmsr == 0xFFFF) return false;
    bmsr = mii_read(1);
    return (bmsr & 0x0004) != 0;        /* bit2: link durumu */
}

/* ================= TX (M1.4) ================= */

static void tx_reap(void) {
    while (dirty_tx < cur_tx) {
        unsigned entry = (unsigned)(dirty_tx % NUM_TX);
        uint32_t st = inl(io + R_TXSTATUS + entry * 4u);
        if (!(st & TSD_DONE)) break;            /* hala islemde */
        if (st & (TSD_OWIN | TSD_ABORT)) {
            st_tx_err++;
            if (st & TSD_ABORT) {
                outl(io + R_TCR, inl(io + R_TCR) | TCR_CLEARABT);
                outw(io + R_ISR, ISR_TXERR);
            }
        } else {
            st_tx_ok++;
        }
        dirty_tx++;
    }
}

/* ================= RX (M1.2) ================= */

static void rx_overflow_recover(void) {
    uint16_t cbr = inw(io + R_CBR);
    kslog("rtl8139 RXOVW cbr=%u (drop aninda %llu)\n",
          (unsigned)cbr, (unsigned long long)st_rx_drop);
    st_rx_ovw++;
    rx_cur = cbr;                                   /* cihazin yazma konumuna hizala */
    outw(io + R_CAPR, (uint16_t)(cbr - 16));        /* overflow'u veriyle temizle */
}

static void process_rx(void) {
    static uint8_t tmp[65536];

    for (;;) {
        uint16_t cbr = inw(io + R_CBR);
        if (rx_cur == (uint32_t)cbr) break;

        if (RX_BUF_SIZE - rx_cur < 4) {             /* header sinira tam sigmiyor */
            rx_cur = 0;
            continue;
        }
        const uint8_t* d = rx_buf + rx_cur;
        uint32_t hdr;
        memcpy(&hdr, d, 4);
        uint16_t size   = (uint16_t)(hdr >> 16);     /* cerceve + 4 (CRC dahil) */
        uint16_t status = (uint16_t)(hdr & 0xFFFF);

        if (!(status & RXT_OK)) break;               /* henuz yazilmadi: bekle */

        if (size < 8 || size > 1514u + 4u) {         /* gecersiz boyut: senkron kaybi */
            kslog("rtl8139 RX gecersiz size=%u status=%04x (senkron kaybi)\n",
                  (unsigned)size, (unsigned)status);
            rx_overflow_recover();
            break;
        }

        if (status & RXT_ERRORS) {                   /* M1.2: hatali cerceveyi dus */
            st_rx_err++;
            rx_cur = (rx_cur + 4u + size + 3u) & (RX_BUF_SIZE - 4);
            continue;
        }

        st_rx_ok++;
        if (rx_cur + 4u + size > RX_BUF_SIZE) {
            /* ring sonunu asan (yesil) paket: parca1 ucta, devam offset 0'da */
            uint32_t part1  = RX_BUF_SIZE - rx_cur - 4;
            uint32_t remain = (uint32_t)size - 4u - part1;
            if (part1 + remain > sizeof(tmp)) { rx_overflow_recover(); break; }
            memcpy(tmp, rx_buf + rx_cur + 4, part1);
            memcpy(tmp + part1, rx_buf, remain);
            net_handle_eth(tmp, size - 4);
            rx_cur = (4u + remain + 3u) & (RX_BUF_SIZE - 4);
        } else {
            net_handle_eth(d + 4, size - 4);
            rx_cur = (rx_cur + 4u + size + 3u) & (RX_BUF_SIZE - 4);
        }
    }
    outw(io + R_CAPR, (rx_cur >= 16) ? (uint16_t)(rx_cur - 16) : 0);
}

/* ================= multicast filtre / RX modu (M1.3) ================= */

/* Ethernet CRC-32 (yansimali polinom, giris ~0, son XOR yok) -> 8139too ether_crc */
static uint32_t ether_crc(const uint8_t* data, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320u : 0);
    }
    return crc;
}

static void apply_rx_mode(void) {
    uint32_t rcr = RCR_BASE | RCR_ACBCST | RCR_ACPHYS;
    uint32_t mar0 = 0, mar1 = 0;

    if (promisc) {
        rcr |= RCR_ACALL | RCR_ACMULT;
        mar0 = mar1 = 0xFFFFFFFFu;          /* tum multicast'lar da kabul */
    } else if (mcast_n > 0) {
        rcr |= RCR_ACMULT;
        for (int i = 0; i < mcast_n; i++) {
            uint32_t bit = ether_crc(mcast[i], 6) >> 26;   /* Ust 6 bit = hash indeksi */
            (bit & 0x20) ? (mar1 |= 1u << (bit & 31)) : (mar0 |= 1u << (bit & 31));
        }
    } else {
        /* multicast listesi bos: IPv6 NDP (ff02::) gibi gruplar calissin diye
           tum multicast'lar kabul edilir (MAR all-ones). */
        rcr |= RCR_ACMULT;
        mar0 = mar1 = 0xFFFFFFFFu;
    }

    outl(io + R_RCR, rcr);
    outl(io + R_MAR0, mar0);
    outl(io + R_MAR0 + 4, mar1);
}

/* ================= gonderim ================= */

} /* namespace */

extern "C" bool rtl8139_init(uint16_t io_base, uint8_t irq, uint8_t bus, uint8_t slot, uint8_t func) {
    io = io_base;
    g_nic_irq = irq;

    pci_set_bus_master(bus, slot, func);       /* Komut bit2: DMA icin sart */

    /* M1.1: MAC oncelikle 93C46 EEPROM'dan; olmazsa IDR0-5 kayitlarindan */
    if (mac_from_eeprom())
        kslog("rtl8139: MAC 93C46 EEPROM sozcuk 7-9'dan okundu\n");
    else {
        for (int i = 0; i < 6; i++) mac[i] = inb(io + (uint16_t)i);
        kslog("rtl8139: MAC IDR0-5 kayitlarindan okundu\n");
    }
    if (!mac_valid(mac)) { kslog("rtl8139: gecersiz MAC\n"); return false; }

    /* M1.5: dusuk guc modundan cikar + chipset uyumlu config */
    if (has_hltclk()) outb(io + R_HLTCLK, 0x52);   /* 'R': saati serbest birak */
    outb(io + R_CONFIG1, 0x00);                    /* SLEEP/PWRDN temizle */

    outb(io + R_CMD, CMD_RESET);                   /* soft reset */
    for (int i = 0; i < 1000 && (inb(io + R_CMD) & CMD_RESET); i++) io_wait();

    rx_buf = (uint8_t*)pmm_alloc_range(32);        /* 128KB; 64K hizaya yuvarla */
    if (!rx_buf) { kslog("rtl8139: rx tampon ayrilamadi\n"); return false; }
    rx_buf = (uint8_t*)(((uintptr_t)rx_buf + 0xFFFFu) & ~(uintptr_t)0xFFFFu);
    memset(rx_buf, 0, RX_BUF_SIZE);
    rx_cur = 0;

    for (int i = 0; i < NUM_TX; i++) {
        tx_bufs[i] = (uint8_t*)pmm_alloc_frame();
        if (!tx_bufs[i]) return false;
        memset(tx_bufs[i], 0, 4096);
    }
    cur_tx = 0;
    dirty_tx = 0;

    /* config yazmalarini ac */
    outb(io + R_CFG9346, CFG_UNLOCK);

    /* MAC'i cihaza geri yaz (soft reset sonrasi gercek HW'de kaybolabilir) */
    outl(io + R_MAC0, (uint32_t)(mac[0] | mac[1] << 8 | mac[2] << 16 | mac[3] << 24));
    outw(io + R_MAC0 + 4, (uint16_t)(mac[4] | mac[5] << 8));

    outl(io + R_RXSTART, (uint32_t)(uintptr_t)rx_buf);

    /* esikler ayarlanmadan once RxTx etkinlestirilmeli */
    outb(io + R_CMD, CMD_RX_EN | CMD_TX_EN);

    outl(io + R_RCR, RCR_BASE | RCR_ACBCST | RCR_ACPHYS);
    outl(io + R_TCR, TCR_IFG96 | TCR_DMA | TCR_RETRY);

    if (is_8139b_plus())          /* magic packet taramayi kapat (8139B+) */
        outb(io + R_CONFIG3, (uint8_t)(inb(io + R_CONFIG3) & ~(uint8_t)CFG3_MAGIC));

    outb(io + R_CFG9346, CFG_LOCK);

    for (int i = 0; i < NUM_TX; i++)               /* TSAD0-3: calmali adresler */
        outl(io + R_TXSTART + (uint16_t)i * 4u, (uint32_t)(uintptr_t)tx_bufs[i]);
    outl(io + R_RXMISSED, 0);

    promisc = false;
    apply_rx_mode();                               /* RCR + MAR0-3 */

    /* erken RX kesmesi yok: paket tamamlaninca kesme */
    outw(io + R_MULTIINTR, inw(io + R_MULTIINTR) & 0xF000);

    /* RxTx hala kapaliysa tekrar ac */
    if ((inb(io + R_CMD) & (CMD_RX_EN | CMD_TX_EN)) != (CMD_RX_EN | CMD_TX_EN))
        outb(io + R_CMD, CMD_RX_EN | CMD_TX_EN);

    outw(io + R_IMR, IMR_ALL);
    outw(io + R_ISR, 0xFFFF);                      /* eski kesmeleri temizle */

    up = true;
    kprintf("rtl8139: MAC %02x:%02x:%02x:%02x:%02x:%02x irq=%u io=0x%x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], irq, io);
    kslog("rtl8139 pci up=%d irq=%d io=0x%x rev=0x%05x\n", up, irq, io, chipset_version());
    return true;
}

extern "C" void rtl8139_send(const void* data, uint16_t len) {
    if (!up) return;
    if (len > 1514) len = 1514;
    if (len < 60) len = 60;                        /* chip otomatik pad yapmiyor */

    if (cur_tx - dirty_tx >= (uint32_t)NUM_TX) {
        tx_reap();
        for (int i = 0; i < 100000 && cur_tx - dirty_tx >= (uint32_t)NUM_TX; i++) {
            io_wait();
            tx_reap();
        }
        if (cur_tx - dirty_tx >= (uint32_t)NUM_TX) {   /* dogrulandi: dusur */
            st_tx_drop++;
            kslog("rtl8139 TX ring dolu, cerceve dusuruldu\n");
            return;
        }
    }

    unsigned entry = (unsigned)(cur_tx % NUM_TX);
    uint8_t* buf = tx_bufs[entry];
    memset(buf, 0, 60);
    memcpy(buf, data, len);

    outl(io + R_TXSTART + (uint16_t)entry * 4u, (uint32_t)(uintptr_t)buf);
    asm volatile("sfence" ::: "memory");           /* DMA buffer'i gorsun */
    outl(io + R_TXSTATUS + (uint16_t)entry * 4u, TSD_FIFO | (uint32_t)len);
    cur_tx++;
}

extern "C" void rtl8139_poll(void) {
    if (!up) return;
    uint16_t isr = inw(io + R_ISR);
    if (!(isr & (ISR_ROK | ISR_TOK | ISR_TXERR | ISR_RXFOV | ISR_RXOVW))) return;
    outw(io + R_ISR, isr);
    if (isr & ISR_TOK)  tx_reap();
    if (isr & ISR_TXERR) { tx_reap(); outw(io + R_ISR, ISR_TXERR); }
    if (isr & (ISR_RXOVW | ISR_RXFOV)) rx_overflow_recover();
    if (isr & ISR_ROK) process_rx();
}

extern "C" void rtl8139_irq(void) {
    if (!up) return;
    uint16_t isr = inw(io + R_ISR);
    if (!isr) return;
    if (isr == 0xFFFF) return;                     /* kart cikarilmis */
    outw(io + R_ISR, isr);

    if (isr & (ISR_PCIERR | ISR_PCSTO | ISR_RXUN | ISR_RXERR)) {
        uint32_t missed = inl(io + R_RXMISSED);
        if (missed) { st_rx_drop += missed; outl(io + R_RXMISSED, 0); }
        if (isr & ISR_PCIERR) kslog("rtl8139 PCIErr\n");
        if (isr & ISR_RXUN)   st_rx_err++;
    }
    if (isr & (ISR_TOK | ISR_TXERR)) tx_reap();
    if (isr & ISR_RXOVW) rx_overflow_recover();
    if (isr & ISR_ROK) process_rx();
}

extern "C" void rtl8139_get_mac(uint8_t out[6]) {
    for (int i = 0; i < 6; i++) out[i] = mac[i];
}

extern "C" bool rtl8139_active(void) { return up; }

extern "C" bool rtl8139_link(void)  { return up ? link_now() : false; }

extern "C" bool rtl8139_set_promisc(bool on) {
    if (!up) return false;
    promisc = on;
    apply_rx_mode();
    return true;
}

extern "C" void rtl8139_mcast_clear(void) {
    mcast_n = 0;
    if (up) apply_rx_mode();
}

extern "C" int rtl8139_mcast_add(const uint8_t a[6]) {
    if (mcast_n >= MCAST_MAX) return -1;
    memcpy(mcast[mcast_n], a, 6);
    mcast_n++;
    if (up) apply_rx_mode();
    return 0;
}

namespace {
static void nic_send(const uint8_t* frame, uint16_t len) { rtl8139_send(frame, len); }
static void nic_poll(void) { rtl8139_poll(); }
static void nic_irq(void)  { rtl8139_irq(); }
static const NicOps rtl8139_ops = { nic_send, nic_poll, nic_irq, rtl8139_active };
}

extern "C" bool rtl8139_nic_probe(const PCIDevice* pci, NicDevice* out) {
    if (up) return false;                                  /* tek ornek */
    if (pci->vendor_id != 0x10EC || pci->device_id != 0x8139) return false;
    uint16_t io_base = (uint16_t)(pci->bar0 & 0xFFFCu);
    if (!rtl8139_init(io_base, pci->irq, pci->bus, pci->slot, pci->func)) return false;
    out->name = "rtl8139";
    out->kind = NIC_WIRED;
    out->irq  = pci->irq;
    out->up   = true;
    rtl8139_get_mac(out->mac);
    out->ops  = &rtl8139_ops;
    return true;
}