#define BUF_PAGES_SIZE 10
#define BUF_BYTE_SIZE (BUF_PAGES_SIZE * PGSIZE)
#define TICKS_BUF_SIZE 20

typedef struct {
    char buf[BUF_BYTE_SIZE + 1];
    int begin;
    int end;
    int count;
} dmesg_buf_entries_t;

typedef struct dmesg_buf {
    dmesg_buf_entries_t entries;
    struct spinlock lock;
} dmesg_buf_t;

void copyout_kernel_dmesg_buf_entries(uint64 ptr);

extern int interrupt_logging;
extern int proc_switch_logging;
extern int syscall_logging;
