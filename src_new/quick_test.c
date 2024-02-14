#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capsicum.h>

int main(void) {
    int dirfd, pt;
    char cwd[1024];

    // Get cwd
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd() error");
        return 1;
    }

    dirfd = open(cwd, O_RDONLY | O_DIRECTORY);

    if (cap_enter() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    /* Open "./foo". */
    FILE* out = fdopen(openat(dirfd, "foo", O_CREAT | O_RDWR), "wb");
    if (!out) {
        perror("");
        return 1;
    }
    
    // Let's write to foo
    fseek(out, 0, SEEK_SET);
    pt = ftell(out);
    printf("%d\n", pt);
    fputc('A', out); 
    pt = ftell(out);
    printf("%d\n", pt);
    fputc('\n', out);
    // Notice that writing a CR does not advance the position
    printf("%d\n", pt);

    fclose(out);
    return 0;
}
