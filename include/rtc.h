#pragma once
/* CMOS Real-Time Clock (RTC) */

#include "kernel.h"

struct RTCDate {
    uint8_t second;
    uint8_t minute;
    uint8_t hour;
    uint8_t day;
    uint8_t month;
    uint16_t year;
    uint8_t century;
};

extern "C" {
void rtc_init(void);
RTCDate rtc_read(void);
uint32_t rtc_timestamp(void);  /* Unix timestamp (sn) */
}
