/* INTENTIONAL INSECURE FIXTURE — demo/test only. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void bad(char *src) {
    char buf[16];
    strcpy(buf, src);
    system(src);
}
