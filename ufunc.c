#include "unistd.h"
#include "stdio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int simple(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j)
{
    return 100;
}

int main()
{
    simple(1,2,3,4,5,6,7,8,9,10);
    while (1) {}
}
