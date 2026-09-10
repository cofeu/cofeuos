#pragma once
/* RTL8139 Ethernet surucusu (port I/O) */

#include "kernel.h"
#include "pci.h"
#include "nic.h"

extern int g_nic_irq;

extern "C" {

bool rtl8139_init(uint16_t io_base, uint8_t irq, uint8_t bus, uint8_t slot, uint8_t func);
bool rtl8139_nic_probe(const PCIDevice* pci, NicDevice* out);
void rtl8139_send(const void* data, uint16_t len);
void rtl8139_poll(void);              /* bayrak odakli RX/TX isleme */
void rtl8139_irq(void);               /* kesme handleri */
void rtl8139_get_mac(uint8_t out[6]);
bool rtl8139_active(void);
bool rtl8139_link(void);              /* MII BMSR bit2 (baglanti durumu) */
bool rtl8139_set_promisc(bool on);    /* tumbirimde (AAP) kabul + MAR all-ones */
void rtl8139_mcast_clear(void);       /* multicast listesini sifirla */
int  rtl8139_mcast_add(const uint8_t a[6]);   /* MAR hash'ine ekle; 0=ok, -1=dolu */

}