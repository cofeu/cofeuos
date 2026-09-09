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
void     net_sockdump(void);                                /* TCP soket durumlari */
bool     net_active(void);
uint32_t net_parse_ip(const char* s, bool* ok);

/* --- tam TCP (RFC 793/1122/6298) --- coklu soket: fd = net_socket() --- */
int      net_socket(void);                                       /* yeni bos soket (fd) veya -1 */
bool     net_tcp_connect(int s, uint32_t ip, uint16_t port);     /* aktif acilis (engelleyici) */
bool     net_tcp_send(int s, const uint8_t* data, uint16_t len); /* tek segment gonder */
uint32_t net_tcp_recv(int s, uint8_t* out, uint32_t cap);        /* gelen veriyi bosalt */
void     net_tcp_wait(int s, uint32_t ticks);                    /* done/err veya zaman asimi */
void     net_tcp_poll(int s);                                    /* retransmisyon zamanlayicisi */
void     net_tcp_poll_all(void);                                 /* tum soketler icin zamanlayici */
void     net_tcp_close(int s);                                   /* aktif FIN kapanisi */
bool     net_tcp_active(int s);                                  /* veri alisverisinde mi */
bool     net_tcp_done(int s);                                    /* kapanis/kurulus (FIN) alindi */
bool     net_tcp_err(int s);                                     /* RST / hata */
uint32_t net_tcp_pending(int s);                                 /* rxr'de bekleyen bayt */
bool     net_tcp_listen(int s, uint16_t port);                   /* pasif acilis (LISTEN) */
int      net_tcp_accept(int s, uint32_t ticks);                  /* kabul edilen soket (fd) veya -1 */
uint32_t net_tcp_recv_some(int s, uint8_t* out, uint32_t cap, uint32_t ticks); /* veri veya zaman asimi */
bool     net_frag_selftest(void);                                /* IPv4 parca birlestirme testi */
bool     net_frag_send_selftest(void);                           /* IPv4 gonderim parcalama testi */

/* --- UDP (RFC 768) --- fd tabanli soketler; datagram kuyrugu per soket --- */
int      net_udp_socket(void);                                   /* yeni bos UDP soket (fd) veya -1 */
bool     net_udp_bind(int s, uint16_t port);                     /* yerel portu bagla (0=otomatik) */
int      net_udp_send_to(int s, uint32_t dst, uint16_t dport,    /* datagram gonder (bayt veya -1) */
                         const uint8_t* data, uint16_t len);
bool     net_udp_wait(int s, uint32_t ticks);                    /* kuyrukta veri veya zaman asimi */
int      net_udp_recv_from(int s, uint8_t* out, uint32_t cap,    /* kuyruktan datagram (0=yok) */
                           uint32_t* src_ip, uint16_t* src_port);
bool     net_udp_close(int s);                                   /* soketi kapat */

}