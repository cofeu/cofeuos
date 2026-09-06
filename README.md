<div align="center">

```
   ██████╗ ██████╗ ███████╗███████╗██╗   ██╗ ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔════╝██╔════╝██║   ██║██╔═══██╗██╔════╝
  ██║     ██║   ██║█████╗  █████╗  ██║   ██║██║   ██║███████╗
  ██║     ██║   ██║██╔══╝  ██╔══╝  ██║   ██║██║   ██║╚════██║
  ╚██████╗╚██████╔╝██║     ███████╗╚██████╔╝╚██████╔╝███████║
   ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝
```

### Sıfırdan yazılmış, x86_64 mimarisi için gerçek bir işletim sistemi çekirdeği

**Kendi bootloader'ı · Kendi dosya sistemi (cofeufs) · Kendi kabuğu · Kendi zamanlayıcısı · Kendi ağ yığını**

[![Mimari](https://img.shields.io/badge/mimari-x86__64-0A5C36?style=for-the-badge&logo=intel&logoColor=white)](#)
[![Dil](https://img.shields.io/badge/dil-C%2B%2B17%20%7C%20NASM-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](#)
[![Boot](https://img.shields.io/badge/boot-özel%20bootloader-blueviolet?style=for-the-badge)](#)
[![Sürüm](https://img.shields.io/badge/sürüm-0.1.0-orange?style=for-the-badge)](#)
[![Platform](https://img.shields.io/badge/çalışma%20ortamı-QEMU%20%7C%20gerçek%20donanım-9cf?style=for-the-badge)](#)
[![Durum](https://img.shields.io/badge/durum-aktif%20geliştirme-brightgreen?style=for-the-badge)](#)

</div>

---

## 🧭 CofeuOS Nedir?

**CofeuOS**, hiçbir üçüncü parti çekirdek, kütüphane veya ön yükleyici kullanmadan, **sıfırdan** inşa edilmiş bağımsız bir **x86_64 işletim sistemi çekirdeğidir**. "Linux üzerine bir katman" ya da bir "framework projesi" değildir — anakart açıldığı andan itibaren donanımla doğrudan konuşan, kendi belleğini yöneten, kendi dosya sistemini formatlayan, kendi süreçlerini zamanlayan ve kendi ağ paketlerini işleyen **uçtan uca bir sistemdir**.

Proje şu üç temel prensip üzerine kuruludur:

| İlke | Açıklama |
|---|---|
| 🔩 **Sıfırdan (from scratch)** | GRUB, Multiboot veya harici bir bootloader **yok**. Gerçek modda başlayan, korumalı moddan geçip 64-bit uzun moda geçen bootloader tamamen elle yazılmıştır. |
| 🧠 **Bağımsız çekirdek** | `libc` yok, `-nostdlib` / `-ffreestanding` ile derlenir. `memcpy`, `strlen` gibi tüm temel fonksiyonlar çekirdeğin kendi içinde yazılmıştır. |
| 💾 **Kendi ekosistemi** | Kendi disk formatı (**cofeufs**), kendi çalıştırılabilir dosya biçimi (**.cexe**) ve kendi kabuk dili vardır. |

> CofeuOS şu anda **0.1.0** sürümünde, aktif olarak geliştirilen ve her gün yeni sürücüler/özellikler kazanan canlı bir sistemdir.

---

## ✨ Özellik Haritası

<table>
<tr><td width="50%" valign="top">

### 🥾 Önyükleme & Çekirdek Çekirdeği
- 16-bit gerçek mod → 32-bit korumalı mod → 64-bit uzun mod geçişini elle yapan NASM bootloader
- Diskten kernel imajını tek geçişte okuyan özel yükleyici
- GDT (Global Descriptor Table) kurulumu
- IDT (Interrupt Descriptor Table) ve ISR/IRQ altyapısı
- PIC yeniden haritalama (`pic_remap`)
- Seri port (COM1) + VGA metin modu çift çıktılı `kprintf` / loglama

### 🧮 Bellek Yönetimi
- Fiziksel bellek yöneticisi (**PMM**) — bit haritalı çerçeve takibi
- Çekirdek içi `kmalloc` heap yöneticisi
- `mem` komutu ile canlı bellek istatistikleri (toplam / yönetilen / boş çerçeve / heap kullanımı)

### ⏱️ Zaman & Gerçek Zamanlı Saat
- PIT tabanlı sistem zamanlayıcısı (`timer`)
- CMOS/RTC sürücüsü ile gerçek tarih-saat okuma
- `uptime`, `date` komutları

</td><td width="50%" valign="top">

### 🧵 Süreç Zamanlama
- Kendi görev zamanlayıcısı (`sched`)
- Açılışta otomatik başlatılan çoklu süreçler (`mercury`, `venus`, `earth`, `byn`)
- `ps`, `spawn`, `run`, `wait`, `kill` ile tam süreç yaşam döngüsü yönetimi
- `.cexe` uzantılı gerçek ELF ikililerini diskten yükleyip çalıştırabilme

### 💽 Depolama & Dosya Sistemi
- ATA/PIO disk sürücüsü + `IDENTIFY` desteği
- **cofeufs**: superblock + bit haritası + inode tablosu içeren, tamamen özgün blok tabanlı dosya sistemi
- `ls`, `cd`, `pwd`, `mkdir`, `touch`, `cat`, `echo`, `wc`, `xxd`, `rm -r`, `lsfs`

### 🌐 Ağ Yığını
- PCI veri yolu taraması ile donanım keşfi
- Realtek **RTL8139** ağ kartı sürücüsü
- Ethernet → ARP → IPv4 → ICMP katmanlı, elle yazılmış ağ yığını
- Açılışta otomatik statik IP yapılandırması, `ifconfig`, `ping`

### 🖥️ Etkileşimli Kabuk
- Tam özellikli komut satırı yorumlayıcısı
- Çıktı yönlendirme desteği (`>`, `>>`)
- Yol çözümleme (`.`/`..` dahil), `reboot` / `poweroff`

</td></tr>
</table>

---

## 🏗️ Sistem Mimarisi

```
┌──────────────────────────────────────────────────────────────────┐
│                         KULLANICI ALANI                          │
│   /sys/basic.cexe        /sys/hello.cexe        (özel .cexe'ler) │
│        (user_demo)             (user2)                           │
└───────────────────────────────┬────────────────────────────────--┘
                                 │  sched_exec_file() / ELF yükleme
┌───────────────────────────────▼──────────────────────────────────┐
│                         COFEUOS ÇEKİRDEĞİ                         │
│                                                                    │
│  ┌───────────┐  ┌───────────┐  ┌────────────┐  ┌───────────────┐ │
│  │   shell   │  │   sched   │  │  cofeufs   │  │   net stack   │ │
│  │  (kabuk)  │  │(zamanlayıcı│ │(dosya sist.)│  │Ethernet/ARP/  │ │
│  │           │  │  + süreç) │  │            │  │  IPv4/ICMP    │ │
│  └─────┬─────┘  └─────┬─────┘  └──────┬─────┘  └───────┬───────┘ │
│        │              │               │                │         │
│  ┌─────▼──────────────▼───────────────▼────────────────▼──────┐  │
│  │        Çekirdek Servisleri: kprintf · pmm · kmalloc          │  │
│  └─────┬─────────────────┬───────────────┬──────────────┬──────┘  │
│        │                 │               │              │         │
│  ┌─────▼─────┐   ┌───────▼─────┐  ┌──────▼─────┐  ┌─────▼──────┐ │
│  │ GDT / IDT │   │ PIT timer / │  │  ATA (PIO) │  │  RTL8139   │ │
│  │ ISR / IRQ │   │  RTC / PIC  │  │  disk sür. │  │  NIC sür.  │ │
│  └───────────┘   └─────────────┘  └────────────┘  └────────────┘ │
└────────────────────────────────┬──────────────────────────────---┘
                                  │  16→32→64-bit geçiş
┌─────────────────────────────────▼─────────────────────────────---┐
│                    BOOTLOADER  (boot/boot.asm)                    │
│      MBR yükleme → Kernel'i diskten okuma → Uzun moda geçiş        │
└─────────────────────────────────────────────────────────────────-┘
```

### Açılış (boot) sırası

1. **BIOS**, `boot/boot.bin`'i MBR olarak belleğe yükler ve çalıştırır.
2. Bootloader gerçek moddan A20 hattı açılışı, GDT kurulumu ve korumalı moda geçişle ilerler; ardından sayfalama kurulup **64-bit uzun moda** atlanır.
3. Bootloader, derleme sırasında hesaplanan sektör sayısı kadar `kernel.bin`'i diskten okuyup `kernel_main()`'e dallanır.
4. Çekirdek sırasıyla: seri port → VGA → GDT/IDT → PIC → zamanlayıcı → RTC → PMM/heap → ATA + cofeufs bağlama (`fs::mount` + `fs::selftest`) → PCI taraması + RTL8139/ağ başlatma → klavye → zamanlayıcı (`sched_init`) ile 4 örnek süreç (`mercury`, `venus`, `earth`, `byn`) başlatır.
5. Son olarak `shell_run()` çağrılarak etkileşimli kabuk devreye girer.

---

## 📂 Proje Yapısı

```
cofeuos/
├── boot/
│   └── boot.asm          # Gerçek→korumalı→uzun mod geçişini yapan NASM bootloader
├── include/               # Ortak başlık dosyaları
│   ├── kernel.h            # Temel tipler, libc benzeri fonksiyon imzaları, KERNEL_VERSION
│   ├── net.h               # Ethernet/ARP/IPv4/ICMP tanımları
│   ├── pci.h  · pmm.h  · rtc.h  · rtl8139.h  · sched.h  · x86.h
├── kernel/                 # C++17 (freestanding) çekirdek kaynak kodu
│   ├── entry.asm            # Uzun moddan C++ giriş noktasına sıçrama
│   ├── isr.asm              # Kesme/istisna giriş noktaları
│   ├── main.cpp             # kernel_main() — tüm alt sistemlerin başlatılma sırası
│   ├── gdt.cpp / idt.cpp / irq.cpp   # Tanımlayıcı tabloları ve kesme yönlendirme
│   ├── memory.cpp / pmm.cpp          # Fiziksel bellek yönetimi ve kmalloc
│   ├── timer.cpp / rtc.cpp           # PIT zamanlayıcı ve gerçek zaman saati
│   ├── keyboard.cpp / vga.cpp / serial.cpp / kprintf.cpp
│   ├── ata.cpp               # ATA/PIO disk sürücüsü
│   ├── cofeufs.cpp           # Özgün cofeufs dosya sistemi uygulaması
│   ├── pci.cpp / rtl8139.cpp / net.cpp   # PCI taraması, NIC sürücüsü, ağ yığını
│   ├── sched.cpp              # Süreç zamanlayıcı ve ELF yükleyici
│   ├── shell.cpp               # Etkileşimli komut satırı yorumlayıcısı
│   └── util.cpp
├── user/                    # "user_demo" kullanıcı-alanı uygulaması + ortak başlangıç kodu
│   ├── user.c
│   └── cofeu_note.asm
├── user2/
│   └── user2.c              # İkinci örnek kullanıcı uygulaması ("hello")
├── tools/
│   └── mkfs.py              # Host tarafında cofeufs biçimlendirip disk imajına dosya gömen araç
├── linker.ld                # Çekirdek bağlayıcı (linker) betiği
├── Makefile                 # Tüm derleme / çalıştırma / ISO hedefleri
└── cofeuos.iso               # Örnek önyüklenebilir ISO çıktısı
```

---

## ⚙️ Gereksinimler

| Araç | Sürüm / Not | Amaç |
|---|---|---|
| `g++` / `gcc` | C++17 desteği (GCC 9+) | Çekirdek ve kullanıcı-alanı derlemesi |
| `nasm` | 2.14+ | Bootloader ve assembly kaynaklarının derlenmesi |
| `binutils` | `ld`, `objcopy`, `readelf` | Bağlama ve ikili dönüştürme |
| `qemu-system-x86_64` | Herhangi güncel sürüm | Sanal makinede çalıştırma |
| `python3` | 3.6+ | `mkfs.py` ve derleme yardımcı betikleri |
| `xorriso` | — | Önyüklenebilir ISO üretimi (`make iso`) |

Debian/Ubuntu türevlerinde tek komutla kurulum:

```bash
sudo apt update && sudo apt install -y \
    build-essential nasm binutils qemu-system-x86 python3 xorriso
```

Arch tabanlı sistemlerde:

```bash
sudo pacman -S base-devel nasm qemu-full python xorriso
```

---

## 🚀 Kurulum ve Derleme

```bash
git clone https://github.com/cofeu/cofeuos.git
cd cofeuos
make
```

`make` çalıştırıldığında sırasıyla şunlar gerçekleşir:

1. **Çekirdek derlemesi** — `kernel/*.cpp` ve `kernel/*.asm` dosyaları `-std=gnu++17 -ffreestanding -fno-exceptions -fno-rtti -mno-red-zone` gibi bayraklarla derlenip `kernel.elf` → ham `kernel.bin`'e dönüştürülür.
2. **Kullanıcı-alanı derlemesi** — `user/user.c` ve `user2/user2.c`, `-nostdlib -fno-pic` bayraklarıyla derlenip düz (flat) ikililere dönüştürülür ve giriş noktaları (`_start`) hesaplanır.
3. **Bootloader derlemesi** — `boot/boot.asm`, üretilen `kernel.bin` boyutuna göre parametrelenerek NASM ile derlenir.
4. **Disk imajı oluşturma** — `disk.img` (67.584 sektör, ≈33 MB) sıfırdan oluşturulur; bootloader ve kernel imajı ilgili LBA konumlarına yazılır, ardından `tools/mkfs.py` ile cofeufs formatlanıp `.cexe` uygulamaları `/sys` dizinine gömülür.

> **🔒 Yerleşik güvenlik kontrolü:** `kernel.bin` derleme sonunda 127 × 512 bayttan büyükse derleme **bilerek hata verir**, çünkü bootloader'ın tek seferlik disk okuma rutini bu sınırla tasarlanmıştır. Bu, sistemin önyükleme aşamasında sessizce bozulmasını engelleyen bir emniyet mekanizmasıdır.

---

## ▶️ Çalıştırma

| Komut | Açıklama |
|---|---|
| `make run` | Disk imajını QEMU'da grafik pencereli çalıştırır; seri port çıktısı terminale yansıtılır. |
| `make run-headless` | Grafik arayüz olmadan, tamamen terminal (seri konsol) üzerinden çalıştırır — hata ayıklama için idealdir. |
| `make iso` | `disk.img`'yi saran önyüklenebilir bir `cofeuos.iso` üretir (`xorriso`). |
| `make run-iso` | Hem `disk.img`'yi hem üretilen ISO'yu (ikincil CD-ROM olarak) birlikte QEMU'da başlatır. |
| `make clean` | Tüm derleme çıktılarını (ikililer, disk imajı, ISO, nesne dosyaları) temizler. |

Her çalıştırmada sanal bir RTL8139 ağ kartı kullanıcı modu ağına (`-netdev user`) bağlanır; sistem açılışta kendini `10.0.2.15/24` olarak yapılandırır ve `10.0.2.2` üzerinden ağ geçidine erişir — böylece `ping` gibi komutlar kutudan çıktığı gibi test edilebilir.

### Gerçek donanımda çalıştırma

`disk.img` (veya `cofeuos.iso`), `dd` ile bir USB belleğe yazılarak uyumlu x86_64 donanımda da (BIOS/legacy önyükleme ile) denenebilir:

```bash
sudo dd if=disk.img of=/dev/sdX bs=4M status=progress conv=fsync
```

> `/dev/sdX` yerine hedef USB aygıtınızın doğru yolunu yazdığınızdan **mutlaka** emin olun — yanlış aygıt, veri kaybına yol açar.

---

## 🖥️ Kabuk (Shell) Komutları

Sistem açıldığında doğrudan etkileşimli komut satırına düşersiniz. Güncel liste her zaman `help` ile görüntülenebilir:

<table>
<tr><th>Kategori</th><th>Komut</th><th>Açıklama</th></tr>
<tr><td rowspan="2">🧾 Genel</td><td><code>help</code></td><td>Komut listesini gösterir</td></tr>
<tr><td><code>clear</code> / <code>cls</code></td><td>Ekranı temizler</td></tr>
<tr><td rowspan="9">📁 Dosya Sistemi</td><td><code>ls [yol]</code></td><td>Dizin içeriğini listeler</td></tr>
<tr><td><code>cd &lt;yol&gt;</code></td><td>Çalışma dizinini değiştirir (<code>.</code> / <code>..</code> destekli)</td></tr>
<tr><td><code>pwd</code></td><td>Geçerli dizini yazdırır</td></tr>
<tr><td><code>mkdir &lt;ad&gt;</code></td><td>Dizin oluşturur</td></tr>
<tr><td><code>touch &lt;ad&gt;</code></td><td>Boş dosya oluşturur</td></tr>
<tr><td><code>cat &lt;dosya&gt;</code></td><td>Dosya içeriğini ekrana yazdırır</td></tr>
<tr><td><code>echo &lt;metin&gt; [&gt;/&gt;&gt; dosya]</code></td><td>Metin yazdırır; dosyaya yönlendirme destekler</td></tr>
<tr><td><code>wc &lt;dosya&gt;</code></td><td>Satır/kelime/bayt sayımı yapar</td></tr>
<tr><td><code>xxd &lt;dosya&gt;</code></td><td>Onaltılık (hex) döküm gösterir</td></tr>
<tr><td>🗑️ Silme</td><td><code>rm [-r] &lt;yol&gt;</code></td><td>Dosya/dizin siler; <code>-r</code> ile özyinelemeli</td></tr>
<tr><td rowspan="2">📊 Sistem Bilgisi</td><td><code>lsfs</code></td><td>cofeufs durumu ve kullanım istatistikleri</td></tr>
<tr><td><code>mem</code></td><td>Bellek kullanım özeti</td></tr>
<tr><td rowspan="2">⏱️ Zaman</td><td><code>uptime</code></td><td>Sistemin çalışma süresi</td></tr>
<tr><td><code>date</code></td><td>RTC üzerinden tarih/saat</td></tr>
<tr><td rowspan="5">🧵 Süreç Yönetimi</td><td><code>ps</code></td><td>Çalışan süreçleri listeler</td></tr>
<tr><td><code>spawn</code></td><td>Yeni bir dahili süreç başlatır</td></tr>
<tr><td><code>run &lt;dosya.cexe&gt;</code></td><td>Diskteki bir ELF uygulamasını çalıştırır</td></tr>
<tr><td><code>wait &lt;pid&gt;</code></td><td>Bir sürecin sonlanmasını bekler</td></tr>
<tr><td><code>kill &lt;pid&gt;</code></td><td>Bir süreci sonlandırır</td></tr>
<tr><td rowspan="2">🌐 Ağ</td><td><code>ifconfig</code></td><td>Ağ arayüzü bilgisini gösterir</td></tr>
<tr><td><code>ping &lt;ip&gt;</code></td><td>ICMP echo isteği gönderir</td></tr>
<tr><td rowspan="2">🔌 Güç Yönetimi</td><td><code>reboot</code></td><td>Sistemi yeniden başlatır</td></tr>
<tr><td><code>poweroff</code> / <code>exit</code></td><td>Sistemi kapatır</td></tr>
</table>

**Örnek oturum:**

```
cofeuos 0.1.0 - x86_64 boot ediliyor...
mem : 128 MB toplam, ... yonetilen, ... serbest frame, heap ...
fs : cofeufs bagli
net : eth0 10.0.2.15/24 (kapidan 10.0.2.2)
sched: islemler baslatildi (pid 0001, 0002, 0003, 0004)

/ > mkdir deneme
/ > cd deneme
/deneme > echo "merhaba cofeuos" > not.txt
/deneme > cat not.txt
merhaba cofeuos
/deneme > run /sys/hello.cexe
/deneme > ps
/deneme > ping 10.0.2.2
```

---

## 💽 cofeufs Dosya Sistemi

CofeuOS, hiçbir mevcut dosya sistemi standardına (FAT, ext2 vb.) bağlı kalmadan, tamamen kendi tasarımı olan **blok tabanlı, sabit düzenli** bir dosya sistemi kullanır:

| Bölge | LBA Aralığı | İçerik |
|---|---|---|
| Önyükleme sektörü | `0` | Bootloader |
| Çekirdek imajı | `1 – 2047` | `kernel.bin` |
| Superblock | `2048` | Dosya sistemi meta verisi |
| Blok bit haritası | `2050 – 2065` (16 blok) | ~64K veri bloğunun boş/dolu durumu |
| Inode tablosu | `2066 – 2129` (64 blok) | 256 inode × 128 bayt |
| Veri blokları | `2130 – 67583` | Dosya/dizin içerikleri (512 bayt/blok) |

**Inode yapısı (128 bayt):**

```
struct inode {
    char     name[32];     // dosya/dizin adı
    uint16_t type;         // FT_FREE / FT_FILE / FT_DIR
    uint16_t rsv;          // ayrılmış
    uint32_t size;         // bayt cinsinden boyut
    uint32_t blocks[22];   // doğrudan blok işaretçileri (maks. ~11 KB/dosya)
};
```

**Dizin girdisi yapısı (40 bayt):** `inode numarası (4B)` + `ad (32B)` + `tür (1B)` + `dolgu (3B)` — her blokta 12 girdi.

Derleme aşamasında `tools/mkfs.py`, çekirdeğin çalışma zamanındaki biçimlendirme ve bağlama mantığını **birebir taklit ederek**, host makinede `disk.img`'ye doğrudan dosya (örn. `.cexe` uygulamaları) yazabilir — bu sayede kernel her önyüklemede uygulamaları sıfırdan kurmak zorunda kalmaz (idempotent kurulum).

---

## 📦 Kullanıcı Alanı ve `.cexe` Çalıştırılabilir Biçimi

CofeuOS, çekirdekten tamamen ayrık derlenen, düz (flat) ELF ikililerini **`.cexe`** uzantısıyla çalıştırabilir:

- `user/user.c` → derlenip hem çekirdeğe gömülü varsayılan süreç olarak hem de `/sys/basic.cexe` olarak diske yazılır.
- `user2/user2.c` → `/sys/hello.cexe` olarak diske yazılan ikinci örnek uygulama.

### Kendi uygulamanızı ekleme

1. Kaynak dosyanızı `user/` altına (ya da yeni bir dizine) ekleyin.
2. `Makefile`'daki mevcut `user_demo` / `user2` kurallarını örnek alarak `USERFLAGS` (`-Os -m64 -ffreestanding -nostdlib -fno-pic -no-pie ...`) ile derleyip `objcopy` ile düz ikiliğe dönüştürün.
3. `disk.img` hedefindeki `tools/mkfs.py` çağrısına `kaynak.elf:/sys/hedef.cexe` biçiminde yeni bir giriş ekleyin.
4. `make` ile yeniden derleyip kabuktan çalıştırın: `run /sys/hedef.cexe`.

---

## 🌐 Ağ Yığını

`kernel/net.cpp` ve `kernel/rtl8139.cpp`, Realtek **RTL8139** ağ kartı için elle yazılmış sürücü üzerine kurulu, katmanlı bir ağ yığını sunar:

```
┌────────────┐
│    ICMP    │  ← ping isteklerine yanıt / gönderim
├────────────┤
│    IPv4    │  ← paketleme, checksum
├────────────┤
│    ARP     │  ← adres çözümleme + önbellek + bekleme kuyruğu
├────────────┤
│  Ethernet  │  ← çerçeveleme
├────────────┤
│  RTL8139   │  ← PCI üzerinden keşfedilen fiziksel NIC sürücüsü
└────────────┘
```

Açılışta PCI veri yolu taranır, `0x10EC:0x8139` (Realtek RTL8139) cihazı bulunursa sürücü başlatılır ve arayüz otomatik olarak statik IP ile yapılandırılır. `ifconfig` ve `ping` komutları bu yığın üzerinden çalışır.

> Şu an TCP/UDP gibi taşıma katmanı protokolleri yığında yer almıyor; yol haritasında bu katmanın eklenmesi planlanmaktadır.

---

## 🗺️ Yol Haritası

- [ ] TCP/UDP taşıma katmanı ve basit bir soket arayüzü
- [ ] Sanal bellek yönetimi (sayfalama tablolarıyla süreç izolasyonu)
- [ ] Kullanıcı/çekirdek modu ayrımı (ring 0 / ring 3)
- [ ] Dinamik yükleme (relocatable ELF) desteği
- [ ] cofeufs'a alt inode blokları (mevcut ~11 KB dosya boyutu sınırını kaldırma)
- [ ] AHCI/SATA sürücüsü ile daha geniş donanım desteği
- [ ] USB yığını

Yol haritasına katkı önerilerinizi Issues üzerinden paylaşabilirsiniz.

---

## 🧹 Temizleme

```bash
make clean
```

Bu komut `kernel.elf`, `kernel.bin`, `disk.img`, `boot/boot.bin`, `cofeuos.iso`, tüm `*.o` nesne dosyalarını ve geçici `iso_root/` dizinini temizler.

---

## 🐞 Sorun Giderme

| Belirti | Olası Neden / Çözüm |
|---|---|
| `HATA: kernel.bin ... boot tek sektor okumasi max 127*512 ile sinirli!` | Çekirdek ikiliği büyüdü. Eklenen kodu optimize edin veya bootloader'ın yükleme rutinini çok sektörlü okuyacak şekilde genişletin. |
| QEMU penceresi açılıyor ama ekran boş | `make run-headless` ile seri konsol çıktısını doğrudan terminalde izleyerek hangi aşamada takıldığını görün. |
| `xorriso: command not found` | `make iso` / `make run-iso` için `xorriso` paketini kurun. |
| Ağ komutları yanıt vermiyor | QEMU'nun `-netdev user` modunda ICMP her zaman desteklenmeyebilir; host güvenlik duvarı ayarlarını ve QEMU sürümünü kontrol edin. |
| Gerçek donanımda önyükleme başarısız | Sistemin BIOS/Legacy modda (UEFI değil) önyükleme yaptığından ve `disk.img`'nin doğru aygıta yazıldığından emin olun. |

---

## 🤝 Katkıda Bulunma

CofeuOS aktif geliştirilen bir sistemdir ve katkılara açıktır:

1. Depoyu **fork**'layın.
2. Açıklayıcı bir isimle yeni bir dal oluşturun (`git checkout -b ozellik/ahci-surucusu`).
3. Değişikliklerinizi hem `make run` hem `make run-headless` ile test edin.
4. Neyi, neden değiştirdiğinizi açıklayan bir **pull request** açın.

Hata bildirimi ve özellik istekleri için lütfen [Issues](../../issues) sekmesini kullanın.

---

## 📜 Lisans

Bu depoda şu an bir `LICENSE` dosyası bulunmuyor. Projeye açık bir lisans (ör. MIT, GPLv3) eklemek isterseniz depo köküne bir `LICENSE` dosyası ekleyip bu bölümü güncellemeniz önerilir.

---

<div align="center">

**CofeuOS** — donanımla sıfırdan konuşan, kendi kurallarını yazan bir işletim sistemi.

*x86_64 · özgün bootloader · özgün dosya sistemi · özgün ağ yığını*

</div>
