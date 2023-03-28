#define MAX_LOCKS 512

void init_proclock();
int make_lock();
int lock(int);
int unlock(int);
int delete_lock(int);
