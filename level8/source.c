#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct s_auth
{
    char    s[32];
    int     flag;
}              t_auth;

t_auth  *auth;
char    *service;

int     main(void)
{
    char s[128];

    while(1)
    {
        printf("%p, %p \n", auth, service);
        if (!fgets(s, 128, stdin))
            break;
        if (!strncmp(s, "auth ", 5))
        {
            auth = malloc(sizeof(auth));
            memset(auth, 0, sizeof(auth));
            if (strlen(s + 5) < 31)
                strcpy(auth->s, s + 5);
        }
        if (!strncmp(s, "reset", 5))
            free(auth);
        if (!strncmp(s, "service", 6))
            service = strdup(line + 7);
        if (!strncmp(s, "login", 5))
        {
            if (auth->flag)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
}