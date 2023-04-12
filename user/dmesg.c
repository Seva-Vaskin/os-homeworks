#include "kernel/types.h"
#include "user/user.h"
#include "kernel/riscv.h"
#include "kernel/spinlock.h"
#include "kernel/pr_msg.h"

dmesg_buf_entries_t user_buf;

int get_next_pos(int pos) {
    return (pos + 1) % BUF_BYTE_SIZE;
}

int get_end_of_msg(int pos, dmesg_buf_entries_t *buf) {
    pos += strlen(buf->buf + pos);
    if (pos == BUF_BYTE_SIZE) {
        pos = strlen(buf->buf);
    }
    return pos;
}

int print_from_pos(int pos, dmesg_buf_entries_t *buf) {
    int end_pos = get_end_of_msg(pos, buf);
    for (; pos != end_pos; pos = get_next_pos(pos)) {
        char b[2];
        b[1] = '\0';
        b[0] = buf->buf[pos];
        printf("%s", b);
    }
//    if (pos != end_pos || buf->buf[pos] != '\0')
//        panic("dmesg: printing error");
    printf("\n");
    return end_pos;
}


void show_dmesg_buf_entries(dmesg_buf_entries_t *buf) {
    for (int i = buf->begin; buf->count != 0; i++) {
        i = print_from_pos(i, buf);
        if (i == buf->end)
            break;
    }
}

int main() {
    dmesg((char *)&user_buf);
    show_dmesg_buf_entries(&user_buf);
    exit(0);
}