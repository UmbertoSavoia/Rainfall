#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

typedef struct s_str
{
    int num;
    int *p;
}               t_str;

char c[80];

void    m(void)
{
    printf("%s - %ld\n", c, time(0));
}

int     main(int argc, char **argv)
{
    FILE *file;
    t_str *s_1, *s_2;

    s_1 = malloc(sizeof(t_str));
    s_1->num = 1;
    s_1->p = malloc(8);

    s_2 = malloc(sizeof(t_str));
    s_2->num = 2;
    s_2->p = malloc(8);

    strcpy(s_1->p, argv[1]);
    strcpy(s_2->p, argv[2]);

    file = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, file);

    puts("~~");
    return 0;
}