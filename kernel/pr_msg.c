#include <stdarg.h>

#include "kernel/types.h"
#include "kernel/riscv.h"
#include "kernel/defs.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/pr_msg.h"
#include "kernel/param.h"
#include "kernel/proc.h"

void init_dmesg_buf(dmesg_buf_t *buf) {
    for (int i = 0; i < BUF_BYTE_SIZE; i++) {
        buf->entries.buf[i] = '\0';
    }
    buf->entries.begin = 0;
    buf->entries.end = BUF_BYTE_SIZE - 1;
    buf->entries.count = 0;
    initlock(&buf->lock, "dmesg lock");
}

int get_next_pos(int pos) {
    return (pos + 1) % BUF_BYTE_SIZE;
}

int get_end_of_msg(int pos, dmesg_buf_t *buf) {
    pos += strlen(buf->entries.buf + pos);
    if (pos == BUF_BYTE_SIZE) {
        pos = strlen(buf->entries.buf);
    }
    return pos;
}

int get_next_msg_pos(int pos, dmesg_buf_t *buf) {
    return get_next_pos(get_end_of_msg(pos, buf));
}

void print_char(char c) {
    if (!(32 <= c && c <= 126))
        panic("dmesg: unprintable character");
    char buf[2];
    buf[1] = '\0';
    buf[0] = c;
    printf("%s", buf);
}

int print_from_pos(int pos, dmesg_buf_t *buf) {
    int end_pos = get_end_of_msg(pos, buf);
    for (; pos != end_pos; pos = get_next_pos(pos)) {
        print_char(buf->entries.buf[pos]);
    }
    if (pos != end_pos || buf->entries.buf[pos] != '\0')
        panic("dmesg: printing error");
    printf("\n");
    return end_pos;
}

void clear_range(int begin_pos, int end_pos, dmesg_buf_t *buf) {
    if (begin_pos < end_pos) {
        memset(buf->entries.buf + begin_pos, 0, end_pos - begin_pos);
    } else {
        memset(buf->entries.buf + begin_pos, 0, BUF_BYTE_SIZE - begin_pos);
        memset(buf->entries.buf, 0, end_pos);
    }
}

int check_free_space(dmesg_buf_t *buf) {
    if (buf->entries.count == 0) {
        return BUF_BYTE_SIZE;
    } else if (buf->entries.begin <= buf->entries.end) {
        return BUF_BYTE_SIZE - buf->entries.end - 1 + buf->entries.begin;
    } else {
        return buf->entries.begin - buf->entries.end - 1;
    }
}

void delete_first_msg(dmesg_buf_t *buf) {
    int end_of_1st_msg = get_end_of_msg(buf->entries.begin, buf);
    clear_range(buf->entries.begin, end_of_1st_msg, buf);
    buf->entries.begin = get_next_pos(end_of_1st_msg);
    buf->entries.count--;
}

int append_to_end(const char *str, dmesg_buf_t *buf) {
    for (;; str++, buf->entries.end = get_next_pos(buf->entries.end)) {
        if (check_free_space(buf) == 0) {
            delete_first_msg(buf);
            if (buf->entries.count == 0)
                panic("pr_msg: too long message");
        }
        if (buf->entries.buf[buf->entries.end] != '\0')
            panic("pr_msg: write to uncleared space");
        buf->entries.buf[buf->entries.end] = *str;
        if (*str == '\0') {
            break;
        }
    }
    return buf->entries.end;
}

int add_after_end(const char *str, dmesg_buf_t *buf) {
    buf->entries.end = get_next_pos(buf->entries.end);
    buf->entries.count++;
    return append_to_end(str, buf);
}

// debug function
void show_buf(dmesg_buf_t *buf) {
    char b[2];
    b[1] = '\0';
    printf("[%d %d] ", buf->entries.begin, buf->entries.end);
    for (int i = 0; i < BUF_BYTE_SIZE; i++) {
        if (buf->entries.buf[i] == '\0')
            printf("#");
        else {
            b[0] = buf->entries.buf[i];
            printf("%s", b);
        }
    }
    printf("\n");
}

void pr_msg(char *fmt, ...);

void show_dmesg_buf(dmesg_buf_t *buf) {
    acquire(&buf->lock);
    for (int i = buf->entries.begin; buf->entries.count != 0; i++) {
        i = print_from_pos(i, buf);
        if (i == buf->entries.end)
            break;
    }
    release(&buf->lock);
}

static char *get_ticks_str(char *ticks_buf) {
    char *ticks_str = ticks_buf + TICKS_BUF_SIZE - 1;
    *ticks_str = '\0';
    ticks_str--;
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

static void put_char_in_buf(char c, dmesg_buf_t *buf) {
    char str[2];
    str[0] = c;
    str[1] = '\0';
    append_to_end(str, buf);
}

static char digits[] = "0123456789abcdef";

static void
printint(int xx, int base, int sign, dmesg_buf_t *dmesg_buf) {
    char buf[16];
    int i;
    uint x;

    if (sign && (sign = xx < 0))
        x = -xx;
    else
        x = xx;

    i = 0;
    do {
        buf[i++] = digits[x % base];
    } while ((x /= base) != 0);

    if (sign)
        buf[i++] = '-';

    while (--i >= 0)
        put_char_in_buf(buf[i], dmesg_buf);
}

static void printptr(uint64 x, dmesg_buf_t *buf) {
    int i;
    put_char_in_buf('0', buf);
    put_char_in_buf('x', buf);
    for (i = 0; i < (sizeof(uint64) * 2); i++, x <<= 4)
        put_char_in_buf(digits[x >> (sizeof(uint64) * 8 - 4)], buf);
}

void pr_msg_to_buf(dmesg_buf_t *buf, char* fmt, va_list ap) {
    if (fmt == 0)
        panic("pr_msg: null fmt");

    int i, c;
    char *s;

    acquire(&buf->lock);
    char ticks_buf[TICKS_BUF_SIZE];
    char *ticks_str = get_ticks_str(ticks_buf);
    add_after_end(ticks_str, buf);


    for (i = 0; (c = fmt[i] & 0xff) != 0; i++) {
        if (c != '%') {
            put_char_in_buf(c, buf);
            continue;
        }
        c = fmt[++i] & 0xff;
        if (c == 0)
            break;
        switch (c) {
            case 'd':
                printint(va_arg(ap,int), 10, 1, buf);
                break;
            case 'x':
                printint(va_arg(ap,int), 16, 1, buf);
                break;
            case 'p':
                printptr(va_arg(ap, uint64), buf);
                break;
            case 's':
                if ((s = va_arg(ap, char*)) == 0)
                s = "(null)";
                for (; *s; s++)
                    put_char_in_buf(*s, buf);
                break;
            case '%':
                put_char_in_buf('%', buf);
                break;
            default:
                // Print unknown % sequence to draw attention.
                put_char_in_buf('%', buf);
                put_char_in_buf(c, buf);
                break;
        }
    }

    release(&buf->lock);
}

static dmesg_buf_t kernel_buf;

void init_kernel_dmesg_buf() {
    init_dmesg_buf(&kernel_buf);
}

void show_kernel_dmesg_buf() {
    show_dmesg_buf(&kernel_buf);
}

static int counter = 0;

void copyout_kernel_dmesg_buf_entries(uint64 ptr) {
    counter++;
    pr_msg("kernel dmesg buf copied %d(%x) times. %s %p", counter, counter, "Now copy to", ptr);
    acquire(&kernel_buf.lock);
    copyout(myproc()->pagetable, ptr, (char *)&kernel_buf.entries, sizeof kernel_buf.entries);
    release(&kernel_buf.lock);
}



// Print to the dmesg buffer. only understands %d, %x, %p, %s.
void pr_msg(char *fmt, ...) {
    va_list myargs;
    va_start(myargs, fmt);
    pr_msg_to_buf(&kernel_buf, fmt, myargs);
    va_end(myargs);
}
