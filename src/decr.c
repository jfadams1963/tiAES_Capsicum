//derc.c
//(c) 2023 2024 J Adams jfa63@duck.com
//Released under the 2-clause BSD license.
//Subroutines are labeled with the FIPS 197 nomenclature.

#include "core.h"


/* AES InvCipher() */
void decr() {

    int r,c,rd;

    //round number nr, i.e., the last round
    /* AddRoundKey() (colomn of state) xor (row of RoundKey) */
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[c][r] ^= w[nr*4+r][c];
        }
    }

    //rounds nr-1 down to 1
    for (rd=nr-1; rd>0; rd--) {
        /* InvShiftRows() */
        //row 1, no rotation
        ns[0][0] = st[0][0];
        ns[0][1] = st[0][1];
        ns[0][2] = st[0][2];
        ns[0][3] = st[0][3];
        //row 2, -1 rotation
        ns[1][0] = st[1][3];
        ns[1][1] = st[1][0];
        ns[1][2] = st[1][1];
        ns[1][3] = st[1][2];
        //row 3, -2 rotation
        ns[2][0] = st[2][2];
        ns[2][1] = st[2][3];
        ns[2][2] = st[2][0];
        ns[2][3] = st[2][1];
        //row 4, -3 rotation
        ns[3][0] = st[3][1];
        ns[3][1] = st[3][2];
        ns[3][2] = st[3][3];
        ns[3][3] = st[3][0];
        cpyns_st();

        /* InvSubBytes() */
        for (r=0; r<4; r++) {
            for (c=0; c<4; c++) {
                st[r][c] = sboxi[st[r][c]];
            }
        }

        /* AddRoundKey() */
        for (r=0; r<4; r++) {
            for (c=0; c<4; c++) {
                st[c][r] ^= w[rd*4+r][c];
            }
        }

        /* InvMixColumns() */
        for (c=0; c<4; c++) {
            ns[0][c] = m14[st[0][c]] ^ m11[st[1][c]] ^ m13[st[2][c]] ^ m9[st[3][c]];
            ns[1][c] = m9[st[0][c]] ^ m14[st[1][c]] ^ m11[st[2][c]] ^ m13[st[3][c]];
            ns[2][c] = m13[st[0][c]] ^ m9[st[1][c]] ^ m14[st[2][c]] ^ m11[st[3][c]];
            ns[3][c] = m11[st[0][c]] ^ m13[st[1][c]] ^ m9[st[2][c]] ^ m14[st[3][c]];
        }
        cpyns_st();
    }//end rounds nr-1 to 1

    /* InvShiftRows() */
    //row 1, no rotation
    ns[0][0] = st[0][0];
    ns[0][1] = st[0][1];
    ns[0][2] = st[0][2];
    ns[0][3] = st[0][3];
    //row 2, -1 rotation
    ns[1][0] = st[1][3];
    ns[1][1] = st[1][0];
    ns[1][2] = st[1][1];
    ns[1][3] = st[1][2];
    //row 3, -2 rotation
    ns[2][0] = st[2][2];
    ns[2][1] = st[2][3];
    ns[2][2] = st[2][0];
    ns[2][3] = st[2][1];
    //row 4, -3 rotation
    ns[3][0] = st[3][1];
    ns[3][1] = st[3][2];
    ns[3][2] = st[3][3];
    ns[3][3] = st[3][0];
    cpyns_st();

    //InvSubBytes()
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[r][c] = sboxi[st[r][c]];
        }
    }

    /* AddRoundKey() */
    //round 0
    rd = 0;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[c][r] ^= w[rd*4+r][c];
        }
    }
}//end decr()


/* Implement CBC mode */
void cbcdec(char* inf, char* of) {

    int i,r,c,s,b,bsz,sz;
    uchar ch,pd;
    FILE *in, *out;

    // Open infile for reading
    in = fopen(inf, "r");
    if (!in) {
        perror("Could not open input file for reading!");
        printf("Cleaning up and exiting gracefully.");
        // Zero out key schedule 
        memset(w, 0, 60*4*sizeof(w[0][0]));
        exit(0);
        }

    // Size of input file 
    fseek(in, 0, SEEK_END);
    bsz = ftell(in) - 16;
    fseek(in, 0, SEEK_SET);

    //Get IV block from the first 16 bytes of in, and fill the temp block
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
             iv[r][c] = fgetc(in);
             tb[r][c] = 0;
        }
    }

    // Do decryption reading from byte array and write
    // to the output file. Close file.
    uchar* barr = malloc(bsz);

    // Use 'i' to index byte array
    i = 0;
    while (i < bsz) {
        // Read bytes into state by _column_ !
        for (c=0; c<4; c++) {
            for (r=0; r<4; r++) {
                st[r][c] =  fgetc(in);

            }
        }
        // Copy state to temp block
        cpyst_tb();
        // Call decr()
        decr();
        // State = state xor IV
        for (r=0; r<4; r++) {
            for (c=0; c<4; c++) {
                st[r][c] = st[r][c] ^ iv[r][c];
            }
        }
        // Copy temp block to IV
        cpytb_iv();
        // Write decrypted bytes to byte array by _column_.
        for (c=0; c<4; c++) {
            for (r=0; r<4; r++) {
                barr[i]  = st[r][c];
                i++;
            }
        }
    }        
    fclose(in);

    // Zero out keymaterial and state 
    memset(w, 0, 60*4*sizeof(w[0][0]));
    memset(tb, 0, 16*sizeof(tb[0][0]));
    memset(iv, 0, 16*sizeof(iv[0][0]));
    memset(ns, 0, 16*sizeof(ns[0][0]));
    memset(st, 0, 16*sizeof(st[0][0]));

    // Get the padding value to truncate byte array
    pd = barr[bsz-1];
    sz = bsz - pd;
 
    // Open outfile for write
    out = fopen(of, "wb");
    // Write the array to out file
    if (!out) {
        perror("out file not open for writing in cbcdec()!\n");
        printf("Cleaning up and exiting gracefully.");
        // Zero out byte array
        memset(barr, 0, bsz*sizeof(barr[0]));
        exit(0);
    }
    for (i=0; i<sz; i++) {
        fputc(barr[i], out);
    }
    fclose(out);

    // Zero out byte array
    memset(barr, 0, bsz*sizeof(barr[0]));
    free(barr);
}//end cbcdec()

