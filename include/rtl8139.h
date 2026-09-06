#pragma once
/* RTL8139 Ethernet surucusu (port I/O) */

#include "kernel.h"

extern int g_nic_irq;   /* isr_dispatch icin cekirdek IRQ numarasi */

extern "C" {

bool rtl8139_init(uint16_t io_base, uint8_t irq, uint8_t bus, uint8_t slot, uint8_t func);
void rtl8139_send(const void* data, uint16_t len);
void rtl8139_poll(void);              /* bayrak odakli RX isleme */
void rtl8139_irq(void);               /* kesme handleri */
void rtl8139_get_mac(uint8_t out[6]);
bool rtl8139_active(void);

}