#pragma once
/* Ethernet + ARP + IPv4 + ICMP (ust yigindan VM ile calisir) */

#include "kernel.h"

extern "C" {

void     net_init(const uint8_t mac[6], uint32_t ip, uint32_t mask, uint32_t gw);
void     net_handle_eth(const uint8_t* frame, uint16_t len);  /* rtl8139'dan gelir */
bool     net_ping(uint32_t ip);                               /* ping gonder, sonuc don */
bool     net_dhcp(void);                                      /* DHCP ile IP al (engelleyici) */
bool     net_dns_resolve(const char* name, uint32_t* out_ip); /* A kaydi coz (engelleyici) */
bool     net_http_get(uint32_t ip, uint16_t port, const char* host,
                      const char* path, char* out, int out_cap);
uint32_t net_get_dns(void);
uint32_t net_get_ip(void);
uint32_t net_get_mask(void);
uint32_t net_get_gw(void);
void     net_ifconfig(void);
bool     net_active(void);
uint32_t net_parse_ip(const char* s, bool* ok);

/* --- tam TCP (RFC 793/1122/6298) --- */
bool     net_tcp_connect(uint32_t ip, uint16_t port);          /* aktif acilis (engelleyici) */
bool     net_tcp_send(const uint8_t* data, uint16_t len);      /* tek segment gonder */
uint32_t net_tcp_recv(uint8_t* out, uint32_t cap);             /* gelen veriyi bosalt */
void     net_tcp_wait(uint32_t ticks);                         /* done/err veya zaman asimi */
void     net_tcp_poll(void);                                   /* retransmisyon zamanlayicisi */
void     net_tcp_close(void);                                  /* aktif FIN kapanisi */
bool     net_tcp_active(void);                                 /* veri alisverisinde mi */
bool     net_tcp_done(void);                                   /* kapanis/kurulus (FIN) alindi */
bool     net_tcp_err(void);                                    /* RST / hata */
uint32_t net_tcp_pending(void);                                /* rxr'de bekleyen bayt */
bool     net_tcp_listen(uint16_t port);                        /* pasif acilis (LISTEN) */
bool     net_tcp_accept(uint32_t ticks);                       /* SYN el sikismasini bekle */
uint32_t net_tcp_recv_some(uint8_t* out, uint32_t cap, uint32_t ticks); /* veri veya zaman asimi */

}