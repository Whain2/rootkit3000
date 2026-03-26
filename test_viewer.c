// auxiliary code for test.sh
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

int main(int argc, char *argv[])
{
    const char *dir = argc > 1 ? argv[1] : ".";

    printf("My PID: %d\n", getpid());
    printf("Press Enter after allow-pid...\n");
    fflush(stdout);

    getchar();

    DIR *d = opendir(dir);
    if (!d) {
        perror("opendir");
        return 1;
    }

    struct dirent *e;
    int count = 0;

    printf("Files in %s:\n", dir);
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.')  {
            printf("  %s\n", e->d_name);
            count++;
        }
    }
    printf("Total: %d\n", count);

    closedir(d);
    return 0;
}