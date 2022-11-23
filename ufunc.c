#include "unistd.h"
#include "stdio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int simple(long x, long y, long z)
{
    printf("%d, %d, %d\n", x, y, z);
    return 100;
}

int main()
{
    long x = 5;
    simple(x, 888, 999);
    while (1) {}
}
