# Bonus 3
Controlliamo le stringhe presenti nel binario:
```
bonus3@RainFall:~$ readelf -p '.rodata' bonus3

String dump of section '.rodata':
  [     8]  r
  [     a]  /home/user/end/.pass
  [    1f]  sh
  [    22]  /bin/sh
```
e passiamo a `gdb`:
```
bonus3@RainFall:~$ gdb -q bonus3
Reading symbols from /home/user/bonus3/bonus3...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0804836c  _init
0x080483b0  strcmp
0x080483b0  strcmp@plt
0x080483c0  fclose
0x080483c0  fclose@plt
0x080483d0  fread
0x080483d0  fread@plt
0x080483e0  puts
0x080483e0  puts@plt
0x080483f0  __gmon_start__
0x080483f0  __gmon_start__@plt
0x08048400  __libc_start_main
0x08048400  __libc_start_main@plt
0x08048410  fopen
0x08048410  fopen@plt
0x08048420  execl
0x08048420  execl@plt
0x08048430  atoi
0x08048430  atoi@plt
0x08048440  _start
0x08048470  __do_global_dtors_aux
0x080484d0  frame_dummy
0x080484f4  main
0x08048620  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048692  __i686.get_pc_thunk.bx
0x080486a0  __do_global_ctors_aux
0x080486cc  _fini
```

### Funzione `main`
Abbiamo due buffer da 66 e da 65 byte, come prima cosa viene chiamata la funzione `fopen` nel seguente modo:
```
FILE *file = fopen("/home/user/end/.pass", "r");
```
successivamente viene settato tutto a zero il primo buffer e viene controllato se `fopen` sia andato a buon fine
e gli argomenti dell'eseguibile siano 2, altrimenti si termina il programma.
Con `fread` viene letto il contenuto del file e copiato nel primo buffer, impostando successivamente a zero il carattere
dato dall'indice ritornato da atoi che prende come argomento il primo argomento del binario.
Poi abbiamo un'altra chiamata a `fread` dove viene copiato il file nel secondo buffer e in fine si controlla con `strcmp`
se il primo buffer e il primo argomento dell'eseguibile sono uguali, così da passare a `execl("/bin/sh", "sh", 0)`.

### Soluzione
Per far si che `strcmp` restituisca `0` dobbiamo inserire come argomento una stringa vuota, così che `atoi` andando
in errore restituisca `0` e verrà così impostato il primo carattere a `0` del buffer. Dato che `strcmp` controlla fino al
carattere `0`, le due stringhe saranno identiche:
```
bonus3@RainFall:~$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ exit
```
```
bonus3@RainFall:~$ su end
Password: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
end@RainFall:~$
```