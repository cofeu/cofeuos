#include "kernel.h"
#include "pci.h"
#include "nic.h"
#include "rtl8139.h"
#include "e1000.h"

namespace {

NicDevice devs[NIC_MAX];
int       ndev   = 0;
int       active = -1;

struct Drv {
    const char* name;
    uint8_t     kind;
    bool        (*probe)(const PCIDevice* pci, NicDevice* out);
};

const Drv DRIVERS[] = {
    { "e1000",   NIC_WIRED, e1000_nic_probe },
    { "rtl8139", NIC_WIRED, rtl8139_nic_probe },
};

} /* namespace */

extern "C" int nic_probe(void) {
    ndev = 0;
    int idx = 0;
    const PCIDevice* pci;
    while ((pci = pci_get(idx++)) != NULL && ndev < NIC_MAX) {
        for (unsigned di = 0; di < sizeof(DRIVERS) / sizeof(DRIVERS[0]) && ndev < NIC_MAX; di++) {
            NicDevice d;
            memset(&d, 0, sizeof(d));
            if (!DRIVERS[di].probe(pci, &d)) continue;
            devs[ndev] = d;
            kprintf("nic[%d]: %s (%s) MAC %02x:%02x:%02x:%02x:%02x:%02x irq=%d\n",
                    ndev, d.name, d.kind == NIC_WIRED ? "kablolu" : "wifi",
                    d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5], d.irq);
            kslog("nic %s probed at %02x:%02x.%x class=%02x/%02x irq=%d\n",
                  d.name, pci->bus, pci->slot, pci->func,
                  pci->class_code, pci->subclass, pci->irq);
            ndev++;
        }
    }

    /* aktif: oncelik kablolu (ethernet); yoksa ilk kart */
    active = -1;
    for (int i = 0; i < ndev; i++)
        if (devs[i].kind == NIC_WIRED) { active = i; break; }
    if (active < 0 && ndev > 0) active = 0;
    return ndev;
}

extern "C" int  nic_count(void)              { return ndev; }
extern "C" int  nic_active_idx(void)         { return active; }

extern "C" bool nic_select(int idx) {
    if (idx < 0 || idx >= ndev) return false;
    active = idx;
    return true;
}

extern "C" const NicDevice* nic_get(int idx) {
    if (idx < 0 || idx >= ndev) return NULL;
    return &devs[idx];
}

extern "C" const NicDevice* nic_current(void) {
    if (active < 0 || active >= ndev) return NULL;
    return &devs[active];
}

extern "C" void nic_send(const uint8_t* frame, uint16_t len) {
    if (active < 0 || active >= ndev) return;
    const NicDevice* d = &devs[active];
    if (d->up && d->ops && d->ops->send) d->ops->send(frame, len);
}

extern "C" bool nic_up(void) {
    const NicDevice* d = nic_current();
    return d && d->up && d->ops && d->ops->active && d->ops->active();
}

extern "C" bool nic_link(void) {
    const NicDevice* d = nic_current();
    if (!d || !d->up || !d->ops || !d->ops->link) return false;
    return d->ops->link();
}

extern "C" void nic_stats(NicStats* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    const NicDevice* d = nic_current();
    if (d && d->up && d->ops && d->ops->stats) d->ops->stats(out);
}

extern "C" void nic_poll_all(void) {
    for (int i = 0; i < ndev; i++)
        if (devs[i].up && devs[i].ops && devs[i].ops->poll) devs[i].ops->poll();
}

extern "C" void nic_irq(int irq) {
    for (int i = 0; i < ndev; i++)
        if (devs[i].up && devs[i].irq == irq && devs[i].ops && devs[i].ops->irq)
            devs[i].ops->irq();
}