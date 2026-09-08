#pragma once
/* NIC soyutlama katmani: coklu ag karti (rtl8139 / e1000 / wifi) tuketicisi.
   net.cpp yalnizca 'aktif' karti gorur; suruculer nic_probe ile takilir. */

#include "kernel.h"
#include "pci.h"

#define NIC_MAX 4

enum { NIC_WIRED = 1, NIC_WIFI = 2 };

struct NicOps {
    void (*send)(const uint8_t* frame, uint16_t len);
    void (*poll)(void);                 /* zamanlayici cagrisi (RX kuyrugu) */
    void (*irq)(void);                  /* PCI kesme handleri */
    bool (*active)(void);
};

struct NicDevice {
    const char* name;
    uint8_t     kind;                   /* NIC_WIRED / NIC_WIFI */
    int         irq;                    /* PCI IRQ satiri (0..15) */
    bool        up;
    uint8_t     mac[6];
    const NicOps* ops;

    /* wifi (kind == NIC_WIFI): 802.11 islemleri */
    int  (*wscan)(char* out, int cap);             /* 0=yok, >0 ssid sayisi */
    bool (*wconnect)(const char* ssid, const char* pass);
    bool (*wactive)(void);
};

extern "C" {

int  nic_probe(void);                    /* PCI uzerinden tum suruculeri dener; kart sayisi */
int  nic_count(void);
int  nic_active_idx(void);
bool nic_select(int idx);                /* aktif karti degistir (bayrak) */
const NicDevice* nic_get(int idx);
const NicDevice* nic_current(void);
void nic_send(const uint8_t* frame, uint16_t len);   /* aktif karta gonder */
bool nic_up(void);                                   /* aktif kart calisiyor mu */
void nic_poll_all(void);
void nic_irq(int irq);

}