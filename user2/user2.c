/* cofeuos ikinci ornek uygulama: sadece bir iletis basar, FS'e bir dosya yazar.
   Ayri ELF imaji (basic.cexe'den bagimsiz) -> coklu uygulama ornegi. */

typedef unsigned long ul;

static ul sys6(ul n, ul a, ul b, ul c) {
    ul r;
    asm volatile("int $0x80"
                 : "=a"(r)
                 : "a"(n), "D"(a), "S"(b), "d"(c)
                 : "rcx", "r11", "memory");
    return r;
}

void _start(void) {
    ul pid = sys6(4, 0, 0, 0);
    const char* msg = "hello.cexe: merhaba, ayri ELF calisiyor!\n";
    sys6(7, (ul)msg, 41, 0);                      /* PUTSN */

    const char* p = "/uspc/hello.txt";
    const char* body = "hello.cexe tarafindan yazildi\n";
    long w = (long)sys6(10, (ul)p, (ul)body, 30); /* FSWRITE */

    char b[96];
    long r = (long)sys6(12, (ul)p, (ul)b, (ul)sizeof(b)); /* FSREAD */
    sys6(7, (ul)"hello.txt: ", 11, 0);
    sys6(7, (ul)b, (ul)r, 0);

    sys6(1, (ul)(20 + pid % 10), 0, 0);           /* EXIT 0x14+ */
}
