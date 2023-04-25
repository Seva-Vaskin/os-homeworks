#include "kernel/types.h"
#include "user.h"

int main(int argc, char **argv) {

  if (argc != 2 || strlen(argv[1]) != 1 || argv[1][0] < '0' || argv[1][0] > '7') {
    printf("chlog usage:\n"
           "Pass a number from 0 to 7.\n"
           "It will be interpreted as a bitmask where:\n"
           "  * mask & 1 - new value for interrupt loging\n"
           "  * mask & 2 - new value for processes switch logging\n"
           "  * mask & 4 - new value for syscall logging\n"
           "\n");
    return 0;
  }
  int mask = argv[1][0] - '0';
  change_logging(mask);

  return 0;
}