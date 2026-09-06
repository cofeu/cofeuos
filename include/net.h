#pragma once
/* Ethernet + ARP + IPv4 + ICMP (ust yigindan VM ile calisir) */

#include "kernel.h"

extern "C" {

void     net_init(const uint8_t mac[6], uint32_t ip, uint32_t mask, uint32_t gw);
void     net_handle_eth(const uint8_t* frame, uint16_t len);  /* rtl8139'dan gelir */
bool     net_ping(uint32_t ip);                               /* ping gonder, sonuc don */
bool     net_dhcp(void);                                      /* DHCP ile IP al (engelleyici) */
bool     net_dns_resolve(const char* name, uint32_t* out_ip); /* A kaydi coz (engelleyici) */
uint32_t net_get_dns(void);
uint32_t net_get_ip(void);
uint32_t net_get_mask(void);
uint32_t net_get_gw(void);
void     net_ifconfig(void);
bool     net_active(void);
uint32_t net_parse_ip(const char* s, bool* ok);

}