; ============================================================================
;  entry.asm - cofeuos 64-bit giris noktasi (0x100008)
;  Boot sektoru buraya "COFEUOS!" magic kontrolunden sonra atlar.
; ============================================================================
BITS 64
default rel

global _start
extern kernel_main
extern __bss_start
extern __bss_end
extern __kstack_top

section .text
_start:
    db 'COFEUOS!'                  ; 8 byte, LBA1'in ilk 8 byte'i = magic

    cli
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov rsp, __kstack_top
    cld

    ; ---- .bss bolgesini sifirla ----
    mov rdi, __bss_start
    mov rcx, __bss_end
    sub rcx, rdi
    xor eax, eax
    rep stosb

    call kernel_main

.hlt:
    cli
    hlt
    jmp .hlt

section .note.GNU-stack noalloc noexec nowrite progbits