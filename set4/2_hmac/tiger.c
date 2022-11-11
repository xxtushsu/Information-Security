/**
 * File :           tiger.c
 * Date :           16 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        2nd exercise of Lab 4 for the course Information Security
 * Description :    This code hashes a message using the tiger method.
 */

#include <stdio.h>
#include <stdlib.h>

#include "s.h"
#include "tiger.h"

#define S1 (S + 256 * 0)
#define S2 (S + 256 * 1)
#define S3 (S + 256 * 2)
#define S4 (S + 256 * 3)

/**
 * This function returns the byte of an unsigned long.
 * @param x The number from which the byte should be retrieved.
 * @param i The index of the byte.
 * @return The byte in question.
 */
unsigned char getByte(unsigned long x, int i){
    return (x >> (unsigned) i) & 0xFFu;
}

/**
 * @param len A pointer to the length of the input.
 * @return An array of bytes of the input.
 */
unsigned char *input(int *len) {
    int i = 0;
    *len = 2;
    unsigned char *in = malloc(*len * sizeof(char));
    unsigned char c = getc(stdin);

    while (!feof(stdin)) { // read input one byte at a time
        in[i] = c;
        c = getc(stdin);
        i++;

        if (i == *len) {  // increase size of array if needed
            *len *= 2;
            in = realloc(in, *len * sizeof(char));
        }
    }

    *len = i;
    return in;
}

/**
 * This function prints the output of tiger hash into stdout.
 */
void output(unsigned long a, unsigned long b, unsigned long c){
    for (int i = 0; i < 64; i += 8) putc(getByte(a, i), stdout);
    for (int i = 0; i < 64; i += 8) putc(getByte(b, i), stdout);
    for (int i = 0; i < 64; i += 8) putc(getByte(c, i), stdout);
}

/**
 * This function outputs an arrays bytes into stdout. TODO: remove this function
 * @param arr The array in question.
 * @param len The length of the array.
 */
void temp(unsigned long *arr, int len) {
    printf("[");
    for (int i = 0; i < len; i++) {
        printf("%lu,", arr[i]);
    }
    printf("]\n");
}

/**
 * This function performs the padded scheme used in tiger hashing.
 * @param input The original input as a byte array (which is freed at the end).
 * @param len The length of the original input that should be changed.
 * @return The input padded in an unsigned long array with length equal to len.
 */
unsigned long *padInput(unsigned char *input, int *len) {
    int newLen = (*len + 1);  // find padding length
    while (newLen % 64 != 56) newLen++;
    input = realloc(input, sizeof(char) * newLen);

    input[*len] = 0x01;  // append Padding bytes
    for (int i = *len + 1; i < newLen; i++) input[i] = 0x00;

    newLen += 8;  // find appending length length
    input = realloc(input, sizeof(char) * newLen);

    unsigned long n = *len * 8;  // append (size * 8)
    for (int i = newLen - 8; i < newLen; i++) {
        input[i] = (unsigned char) (n % 256);
        n /= 256;
    }

    *len = newLen / 8;  // convert to unsigned long array
    unsigned long *padded = malloc(sizeof(unsigned long) * newLen);
    for (int i = 0; i < *len; i++) {
        padded[i] = 0;
        for (int j = 7; j >= 0; j--) {
            padded[i] *= 256;
            padded[i] += input[i * 8 + j];
        }
    }
    free(input);
    return padded;
}

void tigerRound(unsigned long *a, unsigned long *b, unsigned long *c, int m, unsigned long key){
    *c ^= key;
    *a -= S1[getByte(*c, 0*8)] ^ S2[getByte(*c, 2*8)] ^ S3[getByte(*c, 4*8)] ^ S4[getByte(*c, 6*8)];
    *b += S4[getByte(*c, 1*8)] ^ S3[getByte(*c, 3*8)] ^ S2[getByte(*c, 5*8)] ^ S1[getByte(*c, 7*8)];
    *b *= m;
}

/**
 * This function is the inner round F(m) used in tiger hashing.
 */
void tigerInner(unsigned long *a, unsigned long *b, unsigned long *c, int m, unsigned long *keys){
    tigerRound(a, b, c, m, keys[0]);
    tigerRound(b, c, a, m, keys[1]);
    tigerRound(c, a, b, m, keys[2]);
    tigerRound(a, b, c, m, keys[3]);
    tigerRound(b, c, a, m, keys[4]);
    tigerRound(c, a, b, m, keys[5]);
    tigerRound(a, b, c, m, keys[6]);
    tigerRound(b, c, a, m, keys[7]);
}

/**
 * This function is the key scheduler used in tiger hashing.
 * @param W The previous keys to be rescheduled.
 */
void keyScheduler(unsigned long *W){
    W[0] -= W[7] ^ 0xA5A5A5A5A5A5A5A5u;
    W[1] ^= W[0];
    W[2] += W[1];
    W[3] -= W[2] ^ (~W[1] << 19u);
    W[4] ^= W[3];
    W[5] += W[4];
    W[6] -= W[5] ^ (~W[4] >> 23u);
    W[7] ^= W[6];
    W[0] += W[7];
    W[1] -= W[0] ^ (~W[7] << 19u);
    W[2] ^= W[1];
    W[3] += W[2];
    W[4] -= W[3] ^ (~W[2] >> 23u);
    W[5] ^= W[4];
    W[6] += W[5];
    W[7] -= W[6] ^ 0x0123456789ABCDEFu;
}

/**
 * Tiger outer round.
 */
void tigerOuter(unsigned long *a, unsigned long *b, unsigned long *c, unsigned long *W){
    unsigned long saveA = *a, saveB = *b, saveC = *c;
    tigerInner(a, b, c, 5, W);
    keyScheduler(W);
    tigerInner(c, a, b, 7, W);
    keyScheduler(W);
    tigerInner(b, c, a, 9, W);
    *a ^= saveA;
    *b -= saveB;
    *c += saveC;
}

/**
 * TODO
 * @param a
 * @param b
 * @param c
 * @param input
 * @param len
 */
void tiger(unsigned long *a, unsigned long *b, unsigned long *c, unsigned long *input, int len){
    *a = 0x0123456789ABCDEFu;
    *b = 0xFEDCBA9876543210u;
    *c = 0xF096A5B4C3B2E187u;
    for (int i = 0; i < len; i += 8){
        unsigned long *W = &(input[i]);
        tigerOuter(a, b, c, W);
    }
}

/*
int main(int argc, char **argv) {
    int len;
    unsigned char *in = input(&len);

    unsigned long *padded = padInput(in, &len);

    unsigned long a, b, c;
    tiger(&a, &b, &c, padded, len);
    output(a, b, c);

    free(padded);

    return EXIT_SUCCESS;
}
*/