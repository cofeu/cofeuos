; ============================================================================
;  boot.asm - cofeuos 16-bit boot sectoru
;  * BIOS Int13h (LBA) ile kerneli 640KB altindaki ara tampona (0x10000) okur
;  * A20 gate acilir, sayfa tablolari kurulur
;  * 32-bit modda tampon -> 0x100000 kopyalaniP, long mode'a gecilir
;  * Disk duzen: LBA 0 = boot sector, LBA 1.. = kernel.bin
; ============================================================================
BITS 16
ORG 0x7C00

%ifndef KERNEL_SECTORS
%define KERNEL_SECTORS 61       ; LBA 1'den itibaren okunacak sektor sayisi (Makefile verir)
%endif
KERNEL_ENTRY64  equ 0x100008    ; kernel giris noktasi (magic'ten sonrasi)
STAGE_ADDR      equ 0x10000     ; BIOS okuma ara tamponu (640KB sinirinin altinda)
PML4_ADDR       equ 0x70000

start:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, 0x9000
    mov ds, ax
    sti

    mov [boot_drive], dl
    mov dl, [boot_drive]
    call load_kernel
    jc .disk_fail
    jmp .after_load
.disk_fail:
    mov si, msg_diskerr
    call print
    jmp halt

.after_load:
    ; ---- magic dogrula ----
    mov ax, 0x1000
    mov es, ax
    xor di, di                     ; ara tampon basi
    mov si, magic                  ; boot sektorundeki dogru magic
    mov cx, 8
    repe cmpsb                     ; [DS:SI] vs [ES:DI]
    je .magic_ok
    mov si, msg_badmagic
    call print
    jmp halt
.magic_ok:

    ; ---- A20 (fast gate) ----
    in al, 0x92
    test al, 2
    jnz .a20_ok
    or al, 2
    and al, 0xFE
    out 0x92, al
.a20_ok:

    ; ---- BIOS E820 bellek haritasi ----
    ;   sayac : 0x7FF0, girdiler : 0x8000 (24 bayt / entry)
    ;   BIOS tamponu ES:DI ciftini ister; DS/ES'i 0 yap (yigin 0x9000'in altini kullanir).
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov word [0x7FF0], 0
    mov di, 0x8000
    xor ebx, ebx
.e820_next:
    mov eax, 0xE820                       ; Int15/AX=E820
    mov edx, 0x534D4150                   ; 'SMAP'
    mov ecx, 24
    mov dword [di + 20], 1                ; acpi 3.0 boyutu (20 bayt yazilir)
    int 0x15
    jc .e820_done
    cmp eax, 0x534D4150
    jne .e820_done
    inc word [0x7FF0]
    test ebx, ebx
    jz .e820_done
    add di, 24
    cmp di, 0x8F00
    jae .e820_done
    jmp .e820_next
.e820_done:

    ; ---- sayfa tablolari: 0..1GB kimlik haritasi (2MB sayfalar) ----
    ; (16-bit modda 32-bit adresler icin register tabanli erisim sart)
    xor eax, eax
    mov ebx, PML4_ADDR
    mov ecx, (3 * 0x1000) / 4
.zero:
    mov [ebx], eax
    add ebx, 4
    dec ecx
    jnz .zero

    mov ebx, PML4_ADDR
    mov eax, 0x71007                       ; PML4[0] -> PDPT (user)
    mov [ebx], eax
    mov ebx, 0x71000
    mov eax, 0x72007                       ; PDPT[0] -> PD (user)
    mov [ebx], eax

    mov ebx, 0x72000
    mov eax, 0x83                            ; present | rw | PS (2MB), kernel-only
    mov ecx, 512                             ; 512 * 2MB = 1GB identity
.pt:
    mov [ebx], eax
    add eax, 0x200000
    add ebx, 8
    dec ecx
    jnz .pt

    ; ---- long moda giris ----
    mov eax, cr4
    or eax, 0x20                           ; PAE
    mov cr4, eax
    mov ecx, 0xC0000080                    ; EFER MSR
    rdmsr
    or eax, 0x100                          ; LME
    wrmsr
    mov eax, PML4_ADDR
    mov cr3, eax
    lgdt [gdtr]
    mov eax, cr0
    or eax, 1                              ; PE
    mov cr0, eax
    jmp 0x08:pm32

BITS 32
pm32:
    mov ax, 0x10                           ; duz 32-bit veri secicisi
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    cld
    mov esi, STAGE_ADDR
    mov edi, 0x100000
    mov ecx, KERNEL_SECTORS * 512 / 4
    rep movsd                              ; ara tampon -> 0x100000
    mov eax, cr0
    or eax, 0x80000000                     ; PG -> IA-32e aktif
    mov cr0, eax
    jmp 0x18:KERNEL_ENTRY64                ; 64-bit kernel

BITS 16
print:
    lodsb
    test al, al
    jz .done
    mov ah, 0x0E
    mov bx, 7
    int 0x10
    jmp print
.done:
    ret

; ----------------------------------------------------------------------------
; load_kernel: LBA 1..KERNEL_SECTORS -> STAGE_ADDR (tek Int13h okuma)
;  (KERNEL_SECTORS <= 127 oldugu surece gecerlidir)
; ----------------------------------------------------------------------------
load_kernel:
    mov ah, 0x42
    mov dl, [boot_drive]
    mov si, dap
    int 0x13
    ret                     ; CF = BIOS hata bayragi

halt:
    cli
    hlt
    jmp halt

; ---- veri ----
msg_diskerr  db 'disk!', 0
msg_badmagic db 'magic!', 0
magic        db 'COFEUOS!'
boot_drive   db 0

align 4
dap:
            db 0x10
            db 0
            dw KERNEL_SECTORS
            dw 0                    ; offset
            dw STAGE_ADDR >> 4      ; seg   -> STAGE_ADDR
            dd 1                    ; LBA baslangic
            dd 0

align 8
gdtr:
    dw gdt_end - gdt - 1
    dd gdt
gdt:
    dq 0x0000000000000000                  ; null
    dq 0x00CF9A000000FFFF                  ; 0x08 : 32-bit kod
    dq 0x00CF92000000FFFF                  ; 0x10 : veri
    dq 0x00AF9A000000FFFF                  ; 0x18 : 64-bit kod
gdt_end:

times 510-($-$$) db 0
dw 0xAA55