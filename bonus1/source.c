#include <string.h>
#include <unistd.h>

int     main(int argc, char **argv)
{
    int num;
    char dest[40];

    num = atoi(argv[1]);
    if (num <= 9)
    {
        memcpy(dest, argv[2], num*4)
        if (num == 0x574f4c46)
        {
            execl("sh", "/bin/sh", 0);
        }
        return 0;
    }
    return 1;
}