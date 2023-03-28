#include "kernel/types.h"
#include "user/user.h"


void safe_lock(int lock_id) {
    if (lock(lock_id) == -1) {
        fprintf(2, "lock error");
        exit(1);
    }
}

void safe_unlock(int lock_id) {
    if (unlock(lock_id) == -1) {
        fprintf(2, "unlock error");
        exit(1);
    }
}


void interact(int fd_from, int fd_to,  int lock_id) {
    char c;
    int locked = 0;
    while (read(fd_from, &c, 1) > 0) {
        if (locked == 0 && lock_id != -1) {
            safe_lock(lock_id);
            locked = 1;
        }
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
    if (pipe(p1) == -1 || pipe(p2) == -1) {
        fprintf(2, "Pipe error");
    }

    int lock_id = mklock();
    safe_lock(lock_id);

    int pid = fork();
    if (pid == 0) { // child
        close(p2[0]);
        close(p1[1]);

        safe_lock(lock_id);

        interact(p1[0], p2[1], -1);

        safe_unlock(lock_id);

        close(p2[1]);
        close(p1[0]);

    }
    else if (pid > 0) { // parent
        close(p1[0]);
        close(p2[1]);

        for (int i = 0; argv[1][i] != 0; i++) {
            write(p1[1], argv[1] + i, 1);
        }
        close(p1[1]);
        safe_unlock(lock_id);

        interact(p2[0], -1, lock_id);

        close(p2[0]);
        rmlock(lock_id);
    }
    else {
        fprintf(2, "fork error\n");
        rmlock(lock_id);
        exit(1);
    }
    exit(0);
}
