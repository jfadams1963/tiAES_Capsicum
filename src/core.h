/* core.h
 * (c) 2023 2024 J Adams jfa63@duck.com
 * Released under the 2-clause BSD license.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/capsicum.h>

#ifndef CRYPUTILS_H
#define CRYPUTILS_H
#include "cryputils.h"
#endif

/* number of bytes in a word */
#define NB 4

/* data types */
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned char block[4][4];
typedef unsigned char word[4];

/* Globals */
block st,tb,ns,iv; //these are state blocks
unsigned int nk = 8;
unsigned int nr = 14;
unsigned char w[60][4];
