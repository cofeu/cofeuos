; ============================================================================
;  isr.asm - 64-bit interrupt stublari (256 vektor) ve ortak isleyici cikisi
;  C tarafinda:
;    extern "C" uint64_t isr_dispatch(uint64 vec, uint64 err, uint64 ctx);
;  isr_dispatch yeni rsp (task switch icin) dondurur, daha sonra yuklenir.
; ============================================================================
BITS 64
default rel

global isr_stub_table
global isr_common

extern isr_dispatch

section .text

%macro ISR_NOERR 1
isr%1:
    push qword 0
    push qword %1
    jmp isr_common
%endmacro

%macro ISR_ERR 1
isr%1:
    push qword %1
    jmp isr_common
%endmacro

; Calistirilmis tum regleri sakla, vektoru ve hatayi gec, C handler cagir.
isr_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, [rsp + 15*8 + 0]      ; vektor
    mov rsi, [rsp + 15*8 + 8]      ; error code
    mov rdx, rsp                   ; ctx: isr_common sonrasi kayitli rsp
    call isr_dispatch

    mov rsp, rax                   ; task switch olduysa yeni ctx'e gec
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_ERR   16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_NOERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_ERR   30
ISR_NOERR 31
%assign i 32
%rep 224
ISR_NOERR i
%assign i i+1
%endrep

section .data
align 8
isr_stub_table:
%assign i 0
%rep 256
    dq isr%+i
%assign i i+1
%endrep

section .note.GNU-stack noalloc noexec nowrite progbits