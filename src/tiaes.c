//tiaes.c
//(c) 2023 2024 J Adams jfa63@duck.com
//Released under the 2-clause BSD license.

/*
 * Usage: tiaes [e,d] <infile> <outfile>
 */

#ifdef BSD
    #include <readpassphrase.h>
#endif

#ifdef LINUX
    #include <bsd/readpassphrase.h>
#endif

#include "core.h"

#ifndef CRYPUTILS_H
    #define CRYPUTILS_H
    #include "cryputils.h"
#endif


int main(int argc, char* argv[]) {

    //arg checks
    if (argc != 4) {
        printf("Usage: tiaes [e,d] <infile> <outfile>\n");
        return 1;
    }

    // Allocate memory for passphrase
    char pswd[64];

    // Read passphrase
    readpassphrase("Passphrase: ", pswd, sizeof(pswd), 0);
    get_salt();
    uint psz = strlen(pswd);

    // Combine salt and pass
    int cmbsz = 8 + psz;
    uchar comb[cmbsz]; 
    for (int i=0; i<8; i++) {
        comb[i] =  salt[i];
    }
    for (int i=8; i<cmbsz; i++) {
        comb[i] = pswd[i];
    }
    
    // Use the 256-bit hash of the passphrase as the key.
    // The SHA256() function takes a char* as input and returns
    // a unsigned char pointer.
    uchar* key =  SHA256(pswd);

    // Zero-out and deallocate pswd and salt memory location
    explicit_bzero(pswd, psz);
    explicit_bzero(comb, cmbsz);

    // Do key expansion
    ke(key);

    // Zero-out and deallocate key memory location.
    explicit_bzero(key, 32);

    // Do encrypt/decrypt
    if (*argv[1] == 'e') {
        cbcenc(argv[2], argv[3]);

    } else if (*argv[1] == 'd') {;
        cbcdec(argv[2], argv[3]);

    } else {
        // Zero out key schedule
        explicit_bzero(w, 60*4);
        printf("Incorrect args:\n Usage: tiaes [e,d] <infile> <outfile>\n");
    }

    return 0;
}
 
