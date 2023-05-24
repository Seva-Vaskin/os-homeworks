#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/syscall.h"
#include "kernel/memlayout.h"
#include "kernel/riscv.h"

const int N = 20;

#define min(a, b) ((a) < (b) ? (a) : (b))

void
bigfile(int bytes)
{
  char buf[N];

  unlink("bigfile.dat");
  printf("start bigfile.dat writing\n");
  int fd = open("bigfile.dat", O_CREATE | O_RDWR);
  if(fd < 0){
    printf("cannot create bigfile");
    exit(1);
  }
  for(int i = 0, b = bytes; b > 0; i++, b -= N){
    int n_write = min(b, N);
    memset(buf, i, n_write);
    if(write(fd, buf, n_write) != n_write){
      printf("write bigfile failed\n");
      exit(1);
    }
  }
  close(fd);

  printf("start bigfile.dat reading\n");
  fd = open("bigfile.dat", 0);
  if(fd < 0){
    printf("cannot open bigfile\n");
    exit(1);
  }
  int total = 0;
  for(int i = 0; ;i++){
    int cc = read(fd, buf, N);
    total += cc;
    if(cc < 0){
      printf("read bigfile failed\n");
      exit(1);
    }
    if(cc == 0)
      break;
    if(cc != N && total != bytes){
      printf("short read bigfile\n");
      exit(1);
    }
    if(buf[0] != i % 256 || buf[N-1] != i % 256){
      printf("read bigfile wrong data at byte %d\n", i * N);
      printf("expected value: %d\n", i);
      printf("actual values: ");
      for (int j = 0; j < N; j++) {
        printf("%d ", buf[j]);
      }
      printf("\n");
      exit(1);
    }
  }
  close(fd);
  if(total != bytes){
    printf("read bigfile wrong total\n");
    exit(1);
  }
  printf("bigfile test finished successfully\n");
}

int parse_int(char *s) {
  int ans = 0;
  for (; *s != '\0'; s++) {
    if (*s < '0' || *s > '9') {
      printf("Can't parse a number\n");
      exit(1);
    }
    ans = ans * 10 + *s - '0';
  }
  while (*s != '\0') {
  }
  return ans;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: bigfile n_bytes\n");
    exit(1);
  }
  int bytes = parse_int(argv[1]);
  bigfile(bytes);
  exit(0);
}