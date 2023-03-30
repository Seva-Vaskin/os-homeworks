#include "kernel/types.h"
#include "kernel/riscv.h"
#include "kernel/defs.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"

#define BUF_PAGES_SIZE 10
#define BUF_BYTE_SIZE (BUF_PAGES_SIZE * PGSIZE)
#define TICKS_BUF_SIZE 20

struct {
    char buf[BUF_BYTE_SIZE + 1];
    int begin;
    int end;
    int entries_count;
    struct spinlock lock;
} dmesg_buf;

void init_dmesg_buf() {
    for (int i = 0; i < BUF_BYTE_SIZE; i++) {
        dmesg_buf.buf[i] = '\0';
    }
    dmesg_buf.begin = 0;
    dmesg_buf.end = BUF_BYTE_SIZE - 1;
    dmesg_buf.entries_count = 0;
    initlock(&dmesg_buf.lock, "dmesg lock");
}

int get_next_pos(int pos) {
    return (pos + 1) % BUF_BYTE_SIZE;
}

int get_end_of_msg(int pos) {
    pos += strlen(dmesg_buf.buf + pos);
    if (pos == BUF_BYTE_SIZE) {
        pos = strlen(dmesg_buf.buf);
    }
    return pos;
}

int get_next_msg_pos(int pos) {
    return get_next_pos(get_end_of_msg(pos));
}

int print_from_pos(int pos) {
    int end_pos = get_end_of_msg(pos);
    printf("%s", dmesg_buf.buf + pos);
    if (end_pos < pos)
        printf("%s", dmesg_buf.buf);
    printf("\n");
    return end_pos;
}

void clear_range(int begin_pos, int end_pos) {
    if (begin_pos < end_pos) {
        memset(dmesg_buf.buf + begin_pos, 0, end_pos - begin_pos);
    } else {
        memset(dmesg_buf.buf + begin_pos, 0, BUF_BYTE_SIZE - begin_pos);
        memset(dmesg_buf.buf, 0, end_pos);
    }
    dmesg_buf.entries_count--;
}

int check_free_space() {
    if (dmesg_buf.entries_count == 0) {
        return BUF_BYTE_SIZE;
    } else if (dmesg_buf.begin == dmesg_buf.end) {
        panic("pr_msg: begin cannot be equal to end");
    } else if (dmesg_buf.begin < dmesg_buf.end) {
        return BUF_BYTE_SIZE - dmesg_buf.end - 1 + dmesg_buf.begin;
    } else {
        return dmesg_buf.begin - dmesg_buf.end;
    }
}

void alloc_in_buf(int len) {
    if (len > BUF_BYTE_SIZE)
        panic("pr_msg: too large message");
    while (len > check_free_space()) {
        int end_of_1st_msg = get_end_of_msg(dmesg_buf.begin);
        clear_range(dmesg_buf.begin, end_of_1st_msg);
        dmesg_buf.begin = get_next_pos(end_of_1st_msg);
    }
}

int put_in_pos(int pos, const char *str) {
    for (;; str++, pos = get_next_pos(pos)) {
        if (dmesg_buf.buf[pos] != '\0')
            panic("pr_msg: write to uncleared space");
        dmesg_buf.buf[pos] = *str;
        if (*str == '\0') {
            dmesg_buf.end = pos;
            break;
        }
    }
    return pos;
}

int put_in_end(const char *str) {
    return put_in_pos(get_next_pos(dmesg_buf.end), str);
}

// debug function
void show_buf() {
    char buf[2];
    buf[1] = '\0';
    printf("[%d %d] ", dmesg_buf.begin, dmesg_buf.end);
    for (int i = 0; i < BUF_BYTE_SIZE; i++) {
        if (dmesg_buf.buf[i] == '\0')
            printf("#");
        else {
            buf[0] = dmesg_buf.buf[i];
            printf("%s", buf);
        }
    }
    printf("\n");
}

void show_dmesg_buf() {
    acquire(&dmesg_buf.lock);
    for (int i = dmesg_buf.begin;dmesg_buf.entries_count != 0; i++) {
        i = print_from_pos(i);
        if (i == dmesg_buf.end)
            break;
    }
    release(&dmesg_buf.lock);
}

char *get_ticks_str(char *ticks_buf) {
    ticks_buf[TICKS_BUF_SIZE - 1] = '\0';
    char *ticks_str = ticks_buf + TICKS_BUF_SIZE - 1;
    *ticks_str = ' ';
    ticks_str--;
    *ticks_str = ']';
    ticks_str--;
    uint curr_ticks = ticks;
    if (curr_ticks == 0) {
        *ticks_str = '0';
        ticks_str--;
    } else {
        for (; curr_ticks > 0; curr_ticks /= 10, ticks_str--) {
            *ticks_str = '0' + (curr_ticks % 10);
        }
    }
    *ticks_str = '[';
    return ticks_str;
}


void pr_msg(const char *str) {
    if (str == 0)
        return;

    char ticks_buf[TICKS_BUF_SIZE];
    char *ticks_str = get_ticks_str(ticks_buf);
    acquire(&dmesg_buf.lock);
    alloc_in_buf(strlen(ticks_str) + strlen(str) + 1);
    int pos = put_in_end(ticks_str);
    pos = put_in_pos(pos, str);
    dmesg_buf.entries_count++;
    release(&dmesg_buf.lock);
}
