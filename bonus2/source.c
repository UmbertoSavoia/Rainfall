#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int language = 0;

void     greetuser(char *src)
{
    char dest[64];
    char *s;

    if (language == 1)
        strcpy(dest, "\x48\x79\x76\xC3\xA4\xC3\xA4\x20\x70\xC3\xA4\x69\x76\xC3\xA4\xC3\xA4\x20\x00");
    else if (language == 2)
        strcpy(dest, "Goedemiddag! ");
    else if (language == 0)
        strcpy(dest, "Hello ");

    strcat(dest, src);
    puts(dest);
}

int     main(int argc, char **argv, char **envp)
{
    char dest[72];
    char *env = 0;

    if (argc != 3)
        return 1;

    memset(dest, 0, 19);
    strncpy(dest, argv[1], 40);
    strncpy(dest + 40, argv[2], 32);

    env = getenv("LANG");
    if (env)
    {
        if (memcmp(env, "fi", 2) == 0)
            language = 1;
        else if (memcmp(env, "nl", 2) == 0)
            language = 2;
    }
    greetuser(dest);
}