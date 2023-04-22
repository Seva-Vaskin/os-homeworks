#include "kernel/types.h"
#include "user/user.h"

int main() {
  int p[2];
  pipe(p);

  int pid = fork();
  if (pid == 0) {
    close(0);
    dup(p[0]);
    close(p[0]);
    close(p[1]);

    char *argv[2];
    argv[0] = "wc";
    argv[1] = 0;
    exec("wc", argv);
  }
  else if (pid > 0) {
    char buf[512];
    int buf_sz = 0;
    for(; buf_sz < 512;) {
      int n = read(0, buf + buf_sz, 1);
      if (n == 0 || buf[buf_sz++] == '\n')
        break;
    }
    write(p[1], buf, buf_sz);
    close(p[0]);
    close(p[1]);
    exit(0);
  }
  else {
    fprintf(2, "fork error\n");
    exit(1);
  }
  exit(0);
}