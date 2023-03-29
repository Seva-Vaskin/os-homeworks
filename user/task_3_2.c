#include "kernel/types.h"
#include "user/user.h"

char arr[4096 * 10];

int main() {

    uint64 mask;
    pgaccess((uint64)arr, 10, (uint64)&mask);
    printf("mask: %x\n", mask); // mask = 0, no visited pages
    for (int i = 0; i < 4096 * 10; i++) {
        arr[i] = i;
    }
    pgaccess((uint64)arr, 10, (uint64)&mask);
    printf("mask: %x\n", mask); // mask = 0x3FF = 0b1111111111, all 10 pages were visited
    arr[4096 * 5] = 1;
    pgaccess((uint64)arr, 10, (uint64)&mask);
    printf("mask: %x\n", mask); // mask = 0x20 = 0b100000, only 6th page was visited

    exit(0);
}