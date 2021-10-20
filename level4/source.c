#include <stdio.h>
#include <stdlib.h>

int m = 0;

void p(char *s)
{
    printf(s);
}

void    n(void)
{
    char s[536];

    fgets(s, 512, stdin);
    p(s);
    if (m == 16930116)
    {
        system("/bin/cat /home/user/level5/.pass");
    }
}

int     main(void)
{
    n();
    return 0;
}
