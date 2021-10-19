#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char    *p(void)
{
    char s[64];
    unsigned int ret;

    fflush(stdout);
    gets(s);
    ret = (unsigned int)__builtin_return_address(0);
    if ((ret & 0xb0000000) == 0xb0000000)
    {
        printf("%p\n", ret);
        exit(1);
    }
    puts(s);
    return (strdup(s));
}

int     main(void)
{
    p();
    return 0;
}