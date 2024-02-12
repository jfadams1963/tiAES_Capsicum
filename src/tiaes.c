//tiaes.c
// (c) 2023 2024 J Adams jfa63@duck.com
// Released under the 2-clause BSD license.
// Capsicum sandboxed version

/*
 * Usage: tiaes [e,d] <infile> <outfile>
 */

#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <readpassphrase.h>

#include "core.h"

#ifndef CRYPUTILS_H
    #define CRYPUTILS_H
    #include "cryputils.h"
#endif


int main(int argc, char* argv[]) {

    cap_rights_t rights;
    int dirfd, errno;
    char* infn = argv[2];
    char* outfn = argv[3];
    char cwd[1024];
    char* pwd;
    uchar* key;


    //arg checks
    if (argc != 4) {
        printf("Usage: tiaes [e,d] <infile> <outfile>\n");
        return 1;
    }

    // Get cwd
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd() error");
        return 1;
    }

    // Allocate memory for passphrase
    pwd = malloc(1024);
    if (pwd == NULL) {
        perror("Memory allocation error");
        return 1;
    }

    // Read passphrase
    readpassphrase("Passphrase: ", pwd, sizeof(pwd), 0);

    // Use the 256-bit hash of the passphrase as the key.
    // The SHA256() function takes a char* as input and returns
    // a unsigned char pointer.
    key =  SHA256(pwd);
    // Zero-out and deallocate pwd memory location
    memset(pwd, 0, sizeof(pwd)*sizeof(pwd[0]));
    free(pwd);

    // Do key expansion
    ke(key);
    // Zero-out and deallocate key memory location.
    memset(key, 0, 32*sizeof(key[0]));
    free(key);


    // Get fd for current directory 
    dirfd = open(cwd, O_RDONLY | O_DIRECTORY);

    if (dirfd < 0) {
        perror("In main() could not get good fd for cwd!\n");
        printf("dirfd=%d \n", dirfd);
        memset(w, 0, 60*4*sizeof(w[0][0]));
        return 1;
    }

    // Set rights on directory fd
    //cap_rights_init(&rights, CAP_SEEK, CAP_READ, CAP_WRITE);
    //cap_rights_limit(dirfd, &rights);

    // Enter capability mode
    if (cap_enter() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    if (*argv[1] == 'e') {
        // Call cbcenc()
        cbcenc(dirfd, infn, outfn);

    } else if (*argv[1] == 'd') {;
        // Call cbcdec()
        cbcdec(dirfd, infn, outfn);

    } else {
        // Zero out key schedule
        memset(w, 0, 60*4*sizeof(w[0][0]));
        printf("Incorrect args:\n Usage: tiaes [e,d] <infile> <outfile>\n");
    }

    return 0;
}
 
