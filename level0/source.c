#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv, char **envp)
{
    char *arg = argv[1];
    int num = atoi(arg);

    if (num == 423)
    {
        char *exe[2];
        exe[0] = strdup("/bin/sh");
        exe[1] = 0;

        gid_t egid = getegid();
        uid_t euid = geteuid();
        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);

        execv(exe[0], exe);
    }
    else
    {
        fwrite("No !\n", 1, 5, stderr);
    }
}