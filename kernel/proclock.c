#include "types.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proclock.h"

struct {
    struct spinlock lock;

    struct sleeplock sleep_locks[MAX_LOCKS];
    int locks_stack[MAX_LOCKS];
    int is_taken[MAX_LOCKS];
    int locks_stack_pos;

} proclock;


void
initlock(struct spinlock *lk, char *name);

void
initsleeplock(struct sleeplock *lk, char *name);

void
acquiresleep(struct sleeplock *lk);

void
releasesleep(struct sleeplock *lk);

void
acquire(struct spinlock *lk);

void
release(struct spinlock *lk);

void init_proclock() {
    initlock(&proclock.lock, "proclock");
    proclock.locks_stack_pos = 0;
    for (int i = 0; i < MAX_LOCKS; i++) {
        proclock.locks_stack[i] = i;
        proclock.is_taken[i] = 0;
        initsleeplock(&proclock.sleep_locks[i], "proclock");
    }
}

int make_lock() {
    int res;
    acquire(&proclock.lock);
    if (proclock.locks_stack_pos == MAX_LOCKS)
        res = -1;
    else {
        res = proclock.locks_stack[proclock.locks_stack_pos++];
        proclock.is_taken[res] = 1;
    }
    release(&proclock.lock);
    return res;
}

int check_lock_id(int lock_id) {
    int success = 1;
    acquire(&proclock.lock);
    if (lock_id < 0 || lock_id >= MAX_LOCKS || proclock.is_taken[lock_id] == 0)
        success = 0;
    release(&proclock.lock);
    return success;
}

int delete_lock(int lock_id) {
    if (check_lock_id(lock_id) == 0)
        return -1;
    acquire(&proclock.lock);
    proclock.is_taken[lock_id] = 0;
    proclock.locks_stack[--proclock.locks_stack_pos] = lock_id;
    release(&proclock.lock);
    return 0;
}

int lock(int lock_id) {
    if (check_lock_id(lock_id) == 0)
        return -1;
    acquiresleep(&proclock.sleep_locks[lock_id]);
    return 0;
}

int unlock(int lock_id) {
    if (check_lock_id(lock_id) == 0)
        return -1;
    releasesleep(&proclock.sleep_locks[lock_id]);
    return 0;
}
