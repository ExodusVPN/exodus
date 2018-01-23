// #include <stdio.h>
// #include <stdlib.h>


struct flag {
    int f1 : 1;
    int f2 : 2;
    int f3 : 2;
    int f4 : 3;
    int f5 : 1;
};


struct data {
    struct flag a;
    struct flag b;
    int         c;
};
