#include <stdio.h>
#include <string.h>

int     main(int argc, char **argv)
{
    char a[66];
    char b[65];

    FILE *file = fopen("/home/user/end/.pass", "r");

    memset(b, 0, 33);
    if (!file || argc != 2)
        return -1;

    fread(a, 1, 66, file);

    a[atoi(argv[1])] = 0;

    fread(b, 1, 65, file);

    fclose(file);
    if (!strcmp(a, argv[1]))
        execl("/bin/sh", "sh", 0);
    else
        puts(b);
}