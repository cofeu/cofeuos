#include "kernel.h"
#include "x86.h"

namespace {
constexpr uint16_t ATA_DATA   = 0x1F0;
constexpr uint16_t ATA_ERROR  = 0x1F1;
constexpr uint16_t ATA_SECTS  = 0x1F2;
constexpr uint16_t ATA_LBALO  = 0x1F3;
constexpr uint16_t ATA_LBAMI  = 0x1F4;
constexpr uint16_t ATA_LBAHI  = 0x1F5;
constexpr uint16_t ATA_DRIVE  = 0x1F6;
constexpr uint16_t ATA_CMD    = 0x1F7;
constexpr uint16_t ATA_CTRL   = 0x3F6;

bool present = false;

void wait_idle(void) {
    int tries = 0;
    while (tries++ < 10000000) {
        uint8_t st = inb(ATA_CMD);
        if (!(st & 0x80)) return;   /* BSY temiz */
    }
}

void wait_drq(void) {
    int tries = 0;
    while (tries++ < 10000000) {
        uint8_t st = inb(ATA_CMD);
        if (st & 0x80) continue;
        if (st & 0x40) return;      /* DRQ set */
        if (st & 0x01) return;      /* error */
    }
}

void select_drive(uint32_t lba) {
    outb(ATA_DRIVE, (uint8_t)(0xE0 | ((lba >> 24) & 0x0F)));
    io_wait();
    outb(ATA_ERROR, 0);
}

} /* namespace */

extern "C" bool ata_init(void) {
    outb(ATA_CTRL, 0x08);      /* nIEN on, SRST off */
    io_wait();
    outb(ATA_ERROR, 0);
    present = (inb(ATA_CMD) != 0xFF && inb(ATA_CMD) != 0x00);
    return present;
}

extern "C" bool ata_identify(void) {
    uint8_t idbuf[512];
    select_drive(0);
    outb(ATA_SECTS, 0);
    outb(ATA_LBALO, 0);
    outb(ATA_LBAMI, 0);
    outb(ATA_LBAHI, 0);
    outb(ATA_CMD, 0xEC);
    wait_idle();
    if (!(inb(ATA_CMD) & 0x40)) return false;
    insl(ATA_DATA, idbuf, 128);      /* IDENTIFY verisini oku (DRQ tuket) */
    return true;
}

extern "C" bool ata_read_sector(uint32_t lba, void* buf) {
    if (!present) return false;
    wait_idle();
    select_drive(lba);
    outb(ATA_SECTS, 1);
    outb(ATA_LBALO, (uint8_t)(lba & 0xFF));
    outb(ATA_LBAMI, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBAHI, (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_CMD, 0x20);               /* READ SECTOR(S) */
    wait_idle();
    wait_drq();
    if (inb(ATA_CMD) & 0x01) return false;
    insl(ATA_DATA, buf, 128);          /* 512 byte */
    return true;
}

extern "C" bool ata_write_sector(uint32_t lba, const void* buf) {
    if (!present) return false;
    wait_idle();
    select_drive(lba);
    outb(ATA_SECTS, 1);
    outb(ATA_LBALO, (uint8_t)(lba & 0xFF));
    outb(ATA_LBAMI, (uint8_t)((lba >> 8) & 0xFF));
    outb(ATA_LBAHI, (uint8_t)((lba >> 16) & 0xFF));
    outb(ATA_CMD, 0x30);               /* WRITE SECTOR(S) */
    wait_idle();
    wait_drq();
    outsl(ATA_DATA, buf, 128);
    wait_idle();
    outb(ATA_CMD, 0xE7);               /* FLUSH CACHE */
    wait_idle();
    return true;
}