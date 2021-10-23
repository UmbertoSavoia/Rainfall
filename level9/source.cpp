#include <unistd.h>
#include <cstring>

class N
{
public:
    N(int n) : n(n) {
        this->pf = &N::operator+;
    }
    int operator+(N& n) { return this->n + n.n; }
    int operator-(N& n) { return this->n - n.n; }

    void setAnnotation(char *s) {
        memcpy(this->s, s, strlen(s));
    }

    char s[100];
    int (N::*pf)(N&);
    int n;
};

int     main(int argc, char **argv)
{
    if (argc <= 1)
        _exit(1);

    N *a = new N(5);
    N *b = new N(6);

    a->setAnnotation(argv[1]);
    return (b->*(b->pf))(*a);
}