#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fstr
{
    void (*f)();
};

void    n(void)
{
    system("/bin/cat /home/user/level7/.pass");
}

void    m(void)
{
    puts("Nope");
}

int     main(int argc, char **argv)
{
    char *sptr;
    struct fstr *fptr;

    sptr = malloc(64);
    fptr = malloc(4);
    fptr->f = m;

    strcpy(sptr, argv[1]);
    fptr->f();
}