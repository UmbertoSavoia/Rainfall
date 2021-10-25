#include <string.h>
#include <unistd.h>
#include <stdio.h>

void    p(char *dest, char *s)
{
    char buf[4104];

    puts(s);
    read(0, buf, 4096);
    *(strchr(buf, '\n')) = 0;
    strncpy(dest, buf, 20);
}

void    pp(char *dest)
{
    char str1[48];
    char str2[28];
    int len = 0;

    p(str1, " - ");
    p(str2, " - ");
    strcpy(dest, str1);
    while (dest[len])
        len++;
    dest[len] = ' ';
    strcat(dest, str2);
}

int     main(void)
{
    char s[42];

    pp(s);
    puts(s);
    return 0;
}