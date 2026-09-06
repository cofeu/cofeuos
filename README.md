# CofeuOS

**CofeuOS**, x86_64 mimarisi için sıfırdan yazılmış, eğitim/hobi amaçlı basit bir işletim çekirdeğidir. Kendi önyükleyicisi (bootloader), kendi dosya sistemi (**cofeufs**), kendi kabuğu (shell), kooperatif olmayan bir görev zamanlayıcısı ve minimal bir ağ yığınına sahiptir. QEMU üzerinde çalışacak şekilde geliştirilmiştir.

> ⚠️ Bu proje bir hobi/öğrenme projesidir. Üretim ortamlarında veya gerçek donanımda kritik veriyle kullanmak için tasarlanmamıştır.

---

## İçindekiler

- [Özellikler](#özellikler)
- [Proje Yapısı](#proje-yapısı)
- [Gereksinimler](#gereksinimler)
- [Kurulum ve Derleme](#kurulum-ve-derleme)
- [Çalıştırma](#çalıştırma)
- [Kabuk (Shell) Komutları](#kabuk-shell-komutları)
- [cofeufs Dosya Sistemi](#cofeufs-dosya-sistemi)
- [Kullanıcı Alanı Uygulamaları (.cexe)](#kullanıcı-alanı-uygulamaları-cexe)
- [Ağ Desteği](#ağ-desteği)
- [Temizleme](#temizleme)
- [Sorun Giderme](#sorun-giderme)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

---

## Özellikler

- **Önyükleme:** 16/32/64-bit geçişini kendi yapan, NASM ile yazılmış özel bir bootloader (`boot/boot.asm`). Kernel'i diskten tek seferde okuyup 64-bit uzun moda geçiyor.
- **Çekirdek (C++17, freestanding):**
  - GDT / IDT / ISR / IRQ kurulumu ve kesme yönetimi
  - PIT tabanlı zamanlayıcı (`timer`) ve gerçek zaman saati (`rtc`)
  - PS/2 klavye sürücüsü
  - VGA metin modu ve seri port (COM1) çıktısı, `kprintf`
  - Fiziksel bellek yöneticisi (PMM)
  - ATA/PIO disk sürücüsü
  - PCI cihaz taraması
  - RTL8139 ağ kartı sürücüsü
  - Basit görev zamanlayıcı (`sched`): süreç oluşturma, sonlandırma, bekleme
  - Kendi disk tabanlı dosya sistemi: **cofeufs**
  - Etkileşimli bir kabuk (`shell`): dosya/dizin işlemleri, süreç yönetimi, temel ağ komutları
- **Kullanıcı alanı:** Çekirdekten ayrı derlenen, `.cexe` uzantılı düz ELF ikilikleri; `run` komutu ile diskten çalıştırılabilir.
- **Ağ:** Ethernet + ARP + IPv4 + ICMP (temel `ping` desteği için).
- **Görüntü çıktısı:** Ham disk imajı (`disk.img`) ve isteğe bağlı bootable ISO (`cofeuos.iso`, `xorriso` ile).

## Proje Yapısı

```
cofeuos/
├── boot/               # Gerçek modda başlayan, uzun moda geçen NASM bootloader
│   └── boot.asm
├── include/            # Ortak çekirdek başlık dosyaları (kernel.h, net.h, pci.h, ...)
├── kernel/             # C++ çekirdek kaynak kodu (gdt, idt, irq, pmm, cofeufs, shell, sched, net, ...)
├── user/               # "user_demo" kullanıcı-alanı uygulaması kaynakları
├── user2/              # İkinci örnek kullanıcı-alanı uygulaması ("hello")
├── tools/mkfs.py       # Disk imajına host tarafından cofeufs formatında dosya gömen araç
├── linker.ld           # Çekirdek bağlayıcı (linker) betiği
├── Makefile            # Derleme, çalıştırma ve ISO oluşturma hedefleri
└── cofeuos.iso         # Önceden oluşturulmuş örnek ISO çıktısı
```

## Gereksinimler

Aşağıdaki araçların sisteminizde (Linux önerilir) kurulu olması gerekir:

| Araç | Amaç |
|---|---|
| `gcc` / `g++` | Çekirdek (C++17) ve kullanıcı alanı (C) derlemesi |
| `nasm` | Bootloader ve düşük seviye assembly dosyalarının derlenmesi |
| `binutils` (`ld`, `objcopy`, `readelf`) | Bağlama ve ikili dönüştürme işlemleri |
| `qemu-system-x86_64` | Sistemi sanal makinede çalıştırma |
| `python3` | Yardımcı derleme betikleri ve `mkfs.py` |
| `xorriso` | Önyüklenebilir ISO oluşturma (yalnızca `make iso` için) |

Debian/Ubuntu tabanlı bir dağıtımda hızlı kurulum:

```bash
sudo apt update
sudo apt install build-essential nasm binutils qemu-system-x86 python3 xorriso
```

## Kurulum ve Derleme

Depoyu klonlayın:

```bash
git clone https://github.com/cofeu/cofeuos.git
cd cofeuos
```

Ham disk imajını (`disk.img`) derleyin:

```bash
make
```

Bu komut sırasıyla:
1. Çekirdek kaynaklarını (`kernel/*.cpp`, `kernel/*.asm`) derleyip `kernel.elf` → `kernel.bin` üretir,
2. Kullanıcı alanı örneklerini (`user/user.c`, `user2/user2.c`) derler,
3. Bootloader'ı (`boot/boot.asm`) kernel boyutuna göre derler,
4. `tools/mkfs.py` ile `disk.img` üzerinde cofeufs formatlar ve `.cexe` uygulamalarını `/sys` dizinine gömer.

> **Not:** `kernel.bin` boyutu 127 × 512 bayttan büyükse derleme hata verir (bootloader'ın tek seferlik sektör okuma sınırı). Böyle bir durumla karşılaşırsanız çekirdeğe eklenen kodu gözden geçirin veya bootloader'daki yükleme mantığını genişletin.

## Çalıştırma

QEMU içinde grafik pencereli çalıştırma (seri çıktı terminale yansıtılır):

```bash
make run
```

Grafik arayüz olmadan, tamamen terminalden (headless) çalıştırma:

```bash
make run-headless
```

Önyüklenebilir bir ISO oluşturmak için:

```bash
make iso
```

ISO ve disk imajını birlikte (ISO ikincil CD-ROM sürücüsü olarak) çalıştırmak için:

```bash
make run-iso
```

Çalıştırıldığında sanal ağ kartı otomatik olarak kullanıcı modu ağına (`-netdev user`) bağlanır; bu, temel `ping`/ağ komutlarının test edilmesine imkân tanır.

## Kabuk (Shell) Komutları

Sistem açıldığında basit bir komut satırı kabuğuna düşersiniz. `help` yazarak güncel listeyi her zaman görebilirsiniz. Desteklenen başlıca komutlar:

| Komut | Açıklama |
|---|---|
| `help` | Komut listesini gösterir |
| `clear` / `cls` | Ekranı temizler |
| `ls [yol]` | Dizin içeriğini listeler |
| `cd <yol>` | Çalışma dizinini değiştirir |
| `pwd` | Geçerli dizini yazdırır |
| `mkdir <ad>` | Dizin oluşturur |
| `touch <ad>` | Boş dosya oluşturur |
| `cat <dosya>` | Dosya içeriğini yazdırır |
| `echo <metin> [> / >> dosya]` | Metin yazdırır; `>`/`>>` ile dosyaya yönlendirir |
| `wc <dosya>` | Satır/kelime/bayt sayımı |
| `xxd <dosya>` | Onaltılık (hex) döküm |
| `rm [-r] <yol>` | Dosya/dizin siler (`-r` ile özyinelemeli) |
| `lsfs` | Dosya sistemi (cofeufs) durumunu gösterir |
| `mem` | Bellek kullanım bilgisini gösterir |
| `uptime` | Sistemin çalışma süresini gösterir |
| `date` | Gerçek zaman saatinden tarih/saat okur |
| `ps` | Çalışan süreçleri listeler |
| `spawn` | Yeni bir süreç başlatır |
| `run <dosya.cexe>` | Diskteki bir ELF uygulamasını çalıştırır |
| `wait <pid>` | Bir sürecin bitmesini bekler |
| `kill <pid>` | Bir süreci sonlandırır |
| `ifconfig` | Ağ arayüzü bilgisini gösterir |
| `ping <ip>` | ICMP echo isteği gönderir |
| `reboot` | Sistemi yeniden başlatır |
| `poweroff` / `exit` | Sistemi kapatır |

## cofeufs Dosya Sistemi

CofeuOS, disk üzerinde basit, blok tabanlı kendi dosya sistemini (**cofeufs**) kullanır. Düzeni sabit ve öngörülebilirdir:

| Bölge | LBA Aralığı | İçerik |
|---|---|---|
| Boot sektörü | `0` | Önyükleyici |
| Çekirdek imajı | `1 – 2047` | `kernel.bin` |
| Superblock | `2048` | Dosya sistemi meta verisi |
| Blok bit haritası | `2050 – 2065` | Boş/dolu blok takibi (~64K veri bloğu) |
| Inode tablosu | `2066 – 2129` | 256 inode × 128 bayt |
| Veri blokları | `2130+` | Dosya/dizin içerikleri (512 bayt/blok) |

- Her **inode** 128 bayttır: ad (32 bayt), tür, boyut ve doğrudan blok işaretçileri (en fazla 22 blok → dosya başına ~11 KB).
- Her **dizin girdisi** 40 bayttır: inode numarası, ad (32 bayt), tür.
- Host tarafında `tools/mkfs.py`, çekirdeğin kendi biçimlendirme/bağlama mantığını birebir taklit ederek derleme sırasında dosyaları (`.cexe` uygulamaları gibi) doğrudan `disk.img` içine yazar.

## Kullanıcı Alanı Uygulamaları (.cexe)

CofeuOS, çekirdekten bağımsız derlenen düz ikili (flat binary) kullanıcı alanı uygulamalarını `.cexe` uzantısıyla çalıştırabilir:

- `user/user.c` → derlenip gömülür ve varsayılan olarak çekirdeğe (`kernel/user_embed.o`) dahil edilir; ayrıca `/sys/basic.cexe` olarak diske yazılır.
- `user2/user2.c` → `/sys/hello.cexe` olarak diske yazılan ikinci bir örnek uygulama.

Kendi uygulamanızı eklemek için:

1. Kaynak dosyanızı `user/` (veya benzeri bir dizine) ekleyin.
2. `Makefile` içindeki ilgili derleme kurallarını örnek alarak `USERFLAGS` ile derleyin ve `objcopy` ile düz ikiliğe dönüştürün.
3. `disk.img` hedefindeki `tools/mkfs.py` çağrısına `kaynak.elf:/sys/hedef.cexe` biçiminde yeni bir giriş ekleyin.
4. `make` çalıştırıp kabuktan `run /sys/hedef.cexe` ile deneyin.

## Ağ Desteği

`kernel/net.cpp` ve `kernel/rtl8139.cpp`, Realtek RTL8139 ağ kartı için minimal bir sürücü ile birlikte şu protokol katmanlarını sağlar:

- **Ethernet** çerçeveleme
- **ARP** (adres çözümleme, önbellekli)
- **IPv4** paketleme
- **ICMP** (yalnızca `ping` komutunu desteklemek için)

TCP/UDP gibi üst seviye taşıma protokolleri şu an **desteklenmemektedir**; ağ yığını temel bağlanabilirlik testleri (ARP çözümleme, ping) için tasarlanmıştır.

## Temizleme

Derleme çıktısı olan tüm dosyaları (kernel ikilileri, disk imajı, ISO, nesne dosyaları) silmek için:

```bash
make clean
```

## Sorun Giderme

- **"HATA: kernel.bin ... boot tek sektor okumasi max 127*512 ile sinirli!"** — Çekirdek ikiliği bootloader'ın tek seferlik okuma sınırını aştı. Eklediğiniz kodu küçültün ya da bootloader'daki yükleme döngüsünü genişletin.
- **QEMU açılmıyor / ekran boş kalıyor** — `make run-headless` ile seri konsol çıktısını doğrudan terminalde görüntüleyip hata ayıklaması yapabilirsiniz.
- **`xorriso: command not found`** — `make iso` / `make run-iso` için `xorriso` paketini kurmanız gerekir.

## Katkıda Bulunma

Katkılar memnuniyetle karşılanır:

1. Depoyu fork'layın.
2. Yeni bir özellik/düzeltme dalı (branch) oluşturun.
3. Değişikliklerinizi `make run-headless` ile test edin.
4. Açıklayıcı bir başlıkla pull request açın.

Hata bildirimleri ve özellik istekleri için GitHub Issues bölümünü kullanabilirsiniz.

## Lisans

Bu depoda şu an bir `LICENSE` dosyası bulunmamaktadır. Bir lisans eklemek isterseniz (ör. MIT, GPLv3), depo köküne bir `LICENSE` dosyası ekleyip bu bölümü güncellemeniz önerilir.

---

*CofeuOS, x86_64 sistem programlama, önyükleme, dosya sistemleri ve temel ağ yığınları üzerine öğrenmek amacıyla geliştirilen bir hobi işletim sistemidir.*
