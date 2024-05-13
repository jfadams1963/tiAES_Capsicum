/*-
 * tiaes.c
 * (c) 2023 2024 J Adams jfa63@duck.com
 * Released under the 2-clause BSD license.
 * Capsicum sandboxed version
 */

/* Usage: tiaes [-e,-d] <infile> <outfile> */


#include <readpassphrase.h>
#include <sys/stat.h>

#include "core.h"

#ifndef CRYPUTILS_H
    #define CRYPUTILS_H
    #include "cryputils.h"
#endif

/* declaring external fuction ke() */
extern void ke(uchar*);

int
main(int argc, char* argv[])
{
        cap_rights_t rights, inrights, outrights;
        mode_t fmode = S_IRUSR | S_IWUSR | S_IRGRP;
        int dirfd, errno, ch;
        //FILE* ifp = stdin;
        //FILE* ofp = stdout;
        char* infn = argv[2];
        char* outfn = argv[3];
        char cwd[1024];
        char* pwd;
        uchar* key;


        /* arg checks */
        if (argc != 4) {
                printf("Usage: tiaes [-e,-d] <infile> <outfile>\n");
                return 0;
        }

        /* Get cwd */
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
                perror("getcwd() error");
                return 1;
        }

        /* Allocate memory for passphrase */
        pwd = malloc(1024);
        if (pwd == NULL) {
                perror("Memory allocation error");
                return 1;
        }

        /* Read passphrase; we really want this inside cap_enter() */
        readpassphrase("Passphrase: ", pwd, sizeof(pwd), 0);

        /* Get fd for current directory */
        dirfd = open(cwd, O_RDONLY | O_DIRECTORY);

        if (dirfd < 0) {
                perror("In main() could not get good fd for cwd!\n");
                printf("dirfd=%d \n", dirfd);
                memset(w, 0, 60*4*sizeof(w[0][0]));
                return 1;
        }

        /* Set rights on directory fd */
        cap_rights_init(&rights, CAP_FSTAT, CAP_LOOKUP, CAP_CREATE, CAP_PREAD, \
                        CAP_PWRITE, CAP_FCHMOD, CAP_FCNTL);
        cap_rights_limit(dirfd, &rights);

        /*
        // Set rights on stdin and stdout 
        cap_rights_init(&inrights, CAP_FSTAT, CAP_READ);
        if (cap_rights_limit(fileno(ifp), &inrights) < 0 && errno != ENOSYS)
                err(1, "Unable to limit rights for %s", "stdin");

        cap_rights_init(&outrights, CAP_FSTAT, CAP_WRITE, CAP_IOCTL);
        if (cap_rights_limit(fileno(ofp), &outrights) < 0 && errno != ENOSYS)
                err(1 , "Unable to limit rightsfor %s", "stdout");
        */

        /* Enter capability mode */
        if (cap_enter() < 0 && errno != ENOSYS) {
                err(1, "Unable to enter capability mode");
                return 1;
        }

        /* Read passphrase we really want this inside cap_enter() */
        //readpassphrase("Passphrase: ", pwd, sizeof(pwd), 0);

        /* Use the 256-bit hash of the passphrase as the key.
         * The SHA256() function takes a char* as input and returns
         * an unsigned char pointer.
         */
        key =  SHA256(pwd);
        /* Zero-out and deallocate pwd memory location */
        memset(pwd, 0, sizeof(pwd)*sizeof(pwd[0]));
        free(pwd);

        /* Do key expansion */
        ke(key);
        /* Zero-out and deallocate key memory location. */
        memset(key, 0, 32*sizeof(key[0]));
        free(key);

		int rv = (ch = getopt(argc, argv, "ed:"));
		if (rv != -1) {
					switch (ch) {
						case 'e':
                			cbcenc(dirfd, infn, outfn);
							break;
                     	case 'd':
                			cbcdec(dirfd, infn, outfn);
							break;
                     	case '?':
                     	default:
							memset(w, 0, 60*4*sizeof(w[0][0]));
							printf("Incorrect args:\n Usage: tiaes [-e,-d] <infile> <outfile>\n");
							return 0;
					}
		}
		argc -= optind;
		argv += optind;

        /* Clean up file permissions */
        if (fchmodat(dirfd, outfn, fmode, AT_RESOLVE_BENEATH) == -1) {
                printf("chmod 0640 on %s failed.\n", outfn);
                perror("");
                return 1;
        }

        return 0;
}
