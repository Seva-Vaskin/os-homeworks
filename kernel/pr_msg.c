#include <stdarg.h>

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

void print_char(char c) {
    if (!(32 <= c && c <= 126))
        panic("dmesg: unprintable character");
    char buf[2];
    buf[1] = '\0';
    buf[0] = c;
    printf("%s", buf);
}

int print_from_pos(int pos) {
    int end_pos = get_end_of_msg(pos);
    for (; pos != end_pos; pos = get_next_pos(pos)) {
        print_char(dmesg_buf.buf[pos]);
    }
    if (pos != end_pos || dmesg_buf.buf[pos] != '\0')
        panic("dmesg: printing error");
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
}

int check_free_space() {
    if (dmesg_buf.entries_count == 0) {
        return BUF_BYTE_SIZE;
    } else if (dmesg_buf.begin <= dmesg_buf.end) {
        return BUF_BYTE_SIZE - dmesg_buf.end - 1 + dmesg_buf.begin;
    } else {
        return dmesg_buf.begin - dmesg_buf.end - 1;
    }
}

void delete_first_msg() {
    int end_of_1st_msg = get_end_of_msg(dmesg_buf.begin);
    clear_range(dmesg_buf.begin, end_of_1st_msg);
    dmesg_buf.begin = get_next_pos(end_of_1st_msg);
    dmesg_buf.entries_count--;
}

int append_in_end(const char *str) {
    for (;; str++, dmesg_buf.end = get_next_pos(dmesg_buf.end)) {
        if (check_free_space() == 0) {
            delete_first_msg();
            if (dmesg_buf.entries_count == 0)
                panic("pr_msg: too long message");
        }
        if (dmesg_buf.buf[dmesg_buf.end] != '\0')
            panic("pr_msg: write to uncleared space");
        dmesg_buf.buf[dmesg_buf.end] = *str;
        if (*str == '\0') {
            break;
        }
    }
    return dmesg_buf.end;
}

int add_after_end(const char *str) {
    dmesg_buf.end = get_next_pos(dmesg_buf.end);
    dmesg_buf.entries_count++;
    return append_in_end(str);
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

void pr_msg(char *fmt, ...);

static int counter = 0;

void show_dmesg_buf() {
    counter++;
    pr_msg("dmesg showed %d (0x%x) (%p) %s", counter, counter, (long long)counter, "times.");
    acquire(&dmesg_buf.lock);
    for (int i = dmesg_buf.begin; dmesg_buf.entries_count != 0; i++) {
        i = print_from_pos(i);
        if (i == dmesg_buf.end)
            break;
    }
    release(&dmesg_buf.lock);
}

char *get_ticks_str(char *ticks_buf) {
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

static void put_char_in_buf(char c) {
    char buf[2];
    buf[0] = c;
    buf[1] = '\0';
    append_in_end(buf);
}

static char digits[] = "0123456789abcdef";

static void
printint(int xx, int base, int sign)
{
    char buf[16];
    int i;
    uint x;

    if(sign && (sign = xx < 0))
        x = -xx;
    else
        x = xx;

    i = 0;
    do {
        buf[i++] = digits[x % base];
    } while((x /= base) != 0);

    if(sign)
        buf[i++] = '-';

    while(--i >= 0)
        put_char_in_buf(buf[i]);
}

static void
printptr(uint64 x)
{
    int i;
    put_char_in_buf('0');
    put_char_in_buf('x');
    for (i = 0; i < (sizeof(uint64) * 2); i++, x <<= 4)
        put_char_in_buf(digits[x >> (sizeof(uint64) * 8 - 4)]);
}


// Print to the dmesg buffer. only understands %d, %x, %p, %s.
void pr_msg(char *fmt, ...) {
    if (fmt == 0)
        panic("pr_msg: null fmt");

    va_list ap;
    int i, c;
    char *s;

    acquire(&dmesg_buf.lock);
    char ticks_buf[TICKS_BUF_SIZE];
    char *ticks_str = get_ticks_str(ticks_buf);
    add_after_end(ticks_str);


    va_start(ap, fmt);
    for (i = 0; (c = fmt[i] & 0xff) != 0; i++) {
        if (c != '%') {
            put_char_in_buf(c);
            continue;
        }
        c = fmt[++i] & 0xff;
        if (c == 0)
            break;
        switch (c) {
            case 'd':
                printint(va_arg(ap, int), 10, 1);
                break;
            case 'x':
                printint(va_arg(ap, int), 16, 1);
                break;
            case 'p':
                printptr(va_arg(ap, uint64));
                break;
            case 's':
                if ((s = va_arg(ap, char*)) == 0)
                    s = "(null)";
                for (; *s; s++)
                    put_char_in_buf(*s);
                break;
            case '%':
                put_char_in_buf('%');
                break;
            default:
                // Print unknown % sequence to draw attention.
                put_char_in_buf('%');
                put_char_in_buf(c);
                break;
        }
    }
    va_end(ap);

    release(&dmesg_buf.lock);

}
