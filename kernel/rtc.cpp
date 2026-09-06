#include "kernel.h"
#include "x86.h"
#include "rtc.h"

namespace {

uint8_t cmos_read(uint8_t reg) {
    outb(0x70, reg | 0x80);   /* 0x80 = NMI disable */
    io_wait();
    return inb(0x71);
}

void cmos_write(uint8_t reg, uint8_t val) {
    outb(0x70, reg | 0x80);
    io_wait();
    outb(0x71, val);
}

uint8_t bcd_to_bin(uint8_t val) {
    return (uint8_t)(((val >> 4) * 10) + (val & 0x0F));
}

uint8_t read_reg_b(void) {
    return cmos_read(0x0B);
}

bool is_update_in_progress(void) {
    return (cmos_read(0x0A) & 0x80) != 0;
}

} /* namespace */

extern "C" void rtc_init(void) {
    uint8_t reg_b = read_reg_b();

    /* REG_B bit 1: 0=BCD, 1=Binary */
    /* REG_B bit 2: 0=12h, 1=24h */
    /* Biz 24h modunda ve binary olarak okuyacagiz */

    /* Eger BCD modundaysa ve 12h modundaysa, REG_B'yi ayarlayalim */
    if (!(reg_b & 0x04)) {
        /* 12h modunda -> 24h moduna gec */
        reg_b |= 0x04;
    }
    if (!(reg_b & 0x02)) {
        /* BCD modunda -> binary moda gec */
        reg_b |= 0x02;
    }
    cmos_write(0x0B, reg_b);
}

extern "C" RTCDate rtc_read(void) {
    RTCDate rtc;

    /* Update in progress bekleyelim */
    while (is_update_in_progress());

    /* Tum degerleri oku */
    uint8_t sec = cmos_read(0x00);
    uint8_t min = cmos_read(0x02);
    uint8_t hr  = cmos_read(0x04);
    uint8_t day = cmos_read(0x07);
    uint8_t mon = cmos_read(0x08);
    uint8_t yr  = cmos_read(0x09);
    uint8_t cen = cmos_read(0x32);

    /* Bir kez daha okuyup fark varsa tekrar oku (tekrar okuma teknigi) */
    while (is_update_in_progress());
    if (sec != cmos_read(0x00)) {
        sec = cmos_read(0x00);
        min = cmos_read(0x02);
        hr  = cmos_read(0x04);
        day = cmos_read(0x07);
        mon = cmos_read(0x08);
        yr  = cmos_read(0x09);
        cen = cmos_read(0x32);
    }

    /* BCD -> Binary donusum (eger hala BCD ise) */
    uint8_t reg_b = read_reg_b();
    if (!(reg_b & 0x02)) {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hr  = bcd_to_bin(hr);
        day = bcd_to_bin(day);
        mon = bcd_to_bin(mon);
        yr  = bcd_to_bin(yr);
        cen = bcd_to_bin(cen);
    }

    /* 12h -> 24h donusum (eger hala 12h ise) */
    if (!(reg_b & 0x04)) {
        if (hr & 0x80)
            hr = (uint8_t)((hr & 0x7F) + 12);
        if (hr == 24) hr = 0;
    }

    rtc.second = sec;
    rtc.minute = min;
    rtc.hour   = hr;
    rtc.day    = day;
    rtc.month  = mon;
    rtc.year   = (uint16_t)(yr + 2000);
    rtc.century = cen;

    /* Century duzeltmesi */
    if (cen > 0 && rtc.year < 2000) {
        rtc.year = (uint16_t)(cen * 100 + yr);
    }

    return rtc;
}

extern "C" uint32_t rtc_timestamp(void) {
    RTCDate rtc = rtc_read();

    /* Basit Unix timestamp hesabi (1970-01-01'den itibaren) */
    uint32_t days = 0;
    uint16_t y = rtc.year;
    uint8_t m = rtc.month;
    uint8_t d = rtc.day;

    /* Yillarin toplam gun sayisi */
    for (uint16_t i = 1970; i < y; i++) {
        bool leap = (i % 4 == 0 && (i % 100 != 0 || i % 400 == 0));
        days += leap ? 366 : 365;
    }

    /* Aylarin gun sayisi */
    static const uint8_t days_in_month[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    for (uint8_t i = 1; i < m; i++) {
        days += days_in_month[i - 1];
        if (i == 2) {
            bool leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
            if (leap) days++;
        }
    }
    days += (d - 1);

    return days * 86400u + rtc.hour * 3600u + rtc.minute * 60u + rtc.second;
}
