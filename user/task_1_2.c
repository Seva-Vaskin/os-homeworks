#include "kernel/types.h"
#include "user/user.h"

void interact(int fd_from, int fd_to) {
  char c;
  while (read(fd_from, &c, 1) > 0) {
    fprintf(1, "%d: received %c\n", getpid(), c);
    if (fd_to != -1)
      write(fd_to, &c, 1);
  }
}

int main(int argc, char * argv[]) {

  if (argc < 2) {
    fprintf(2, "Not enough arguments\n");
    exit(1);
  }

  int p1[2];
  int p2[2];
  pipe(p1);
  pipe(p2);

  int pid = fork();
  if (pid == 0) { // child
    close(p2[0]);
    close(p1[1]);

    interact(p1[0], p2[1]);

    close(p2[1]);
    close(p1[0]);

    exit(0);
  }
  else if (pid > 0) { // parent
    printf("child id: %d, parent id: %d\n", pid, getpid());
    close(p1[0]);
    close(p2[1]);

    for (int i = 0; argv[1][i] != 0; i++) {
      write(p1[1], argv[1] + i, 1);
    }
    close(p1[1]);

    wait(0);
    interact(p2[0], -1);

    close(p2[0]);

    exit(0);
  }
  else {
    fprintf(2, "fork error\n");
    exit(1);
  }
}