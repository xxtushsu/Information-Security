/**
 * File :           hmac.c
 * Date :           20 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        3nd exercise of Lab 4 for the course Information Security
 * Description :    This code applies hmac to a message and key using tiger as hashing function.
 */

#include <stdio.h>
#include <stdlib.h>

#include "tiger.h"

/**
 * This function appends to bytes arrays together.
 * @param bytesA The first byte array.
 * @param lenA The length of the first byte array.
 * @param bytesB The second byte array.
 * @param lenB The length of the second byte array.
 * @return A new bytes array (bytesA + bytesB) with length = lenA + lenB.
 */
unsigned char *appendBytes(unsigned char *bytesA, int lenA, unsigned char *bytesB, int lenB){
    int len = lenA + lenB;
    unsigned char *bytesC = malloc(sizeof(unsigned char) * len);
    for (int i = 0; i < len; i++) bytesC[i] = (i < lenA) ? bytesA[i] : bytesB[i - lenA];
    return bytesC;
}

/**
 * This function performs bitwise xor between to byte arrays.
 * @param bytesA The first byte array.
 * @param bytesB The second byte array.
 * @param len The shared size of the byte arrays.
 * @return A new byte array (bytesA ^ bytesB).
 */
unsigned char *xorBytes(unsigned char *bytesA, unsigned char *bytesB, int len){
    unsigned char *bytesC = malloc(sizeof(unsigned char) * len);
    for (int i = 0; i < len; i++) bytesC[i] = bytesA[i] ^ bytesB[i];
    return bytesC;
}

/**
 * This function reads the key from stdin.
 * @param len The length of the key that should be updated.
 * @return A byte array representing the key.
 */
unsigned char *inputKey(int *len){
    *len = 64;
    unsigned char *key = malloc(sizeof(unsigned char) * *len);
    unsigned char c = getc(stdin);

    for (int i = 0; i < *len; i++){
        if (c == 0xFFu){
            key[i] = 0x00u;  // pad extra 0x00 bytes.
        } else {
            key[i] = c;
            c = getc(stdin);
        }
    }

    return key;
}

/**
 * This function reads the message form stdin.
 * @param len The length of the message that should be updated.
 * @return A byte array representing the message.
 */
unsigned char *inputMessage(int *len){
    int i = 0;
    *len = 2;
    unsigned char *message = malloc(*len * sizeof(char));
    unsigned char c = getc(stdin);

    while (!feof(stdin)) { // read input one byte at a time
        message[i] = c;
        c = getc(stdin);
        i++;

        if (i == *len) {  // increase size of array if needed
            *len *= 2;
            message = realloc(message, *len * sizeof(char));
        }
    }

    *len = i;
    return message;
}

/**
 * This function coverts the output of a tiger hash input into a byte array.
 * @param a The first output value of tiger hash.
 * @param b The second output value of tiger hash.
 * @param c The third output value of tiger hash.
 * @return a byte array length 24.
 */
unsigned char *tigerToBytes(unsigned long a, unsigned long b, unsigned long c){
    unsigned char *bytes = malloc(sizeof(unsigned char) * 24);
    for (int i = 0; i < 24; i++){
        if (i / 8 == 0) {
            bytes[i] = (a >> (unsigned) i*8) & 0xFFu;
        } else if (i / 8 == 1) {
            bytes[i] = (b >> (unsigned) (i*8 - 64)) & 0xFFu;
        } else {
            bytes[i] = (c >> (unsigned) (i*8 - 128)) & 0xFFu;
        }
    }
    return bytes;
}

/**
 * This function prints bytes from an array into stdout.
 * @param bytes The bytes array in question.
 * @param len The length of the bytes array.
 */
void outputBytes(unsigned char *bytes, int len){
    for (int i = 0; i < len; i++) putc(bytes[i], stdout);
}

/**
 * This function gives I-pad of HMAC.
 * @param len The length of I-pad that should be generated.
 * @return I-pad as a byte array.
 */
unsigned char *ipad(int len){
    unsigned char *bytes = malloc(sizeof(unsigned char) * len);
    for (int i = 0; i < len; i++) bytes[i] = 0x36u;
    return bytes;
}

/**
 * This function gives o-pad of HMAC.
 * @param len The length of o-pad that should be generated.
 * @return O-pad as a byte array.
 */
unsigned char *opad(int len){
    unsigned char *bytes = malloc(sizeof(unsigned char) * len);
    for (int i = 0; i < len; i++) bytes[i] = 0x5cu;
    return bytes;
}

/**
 * This function performs HMAC on a message and key using tiger hash.
 * @param key The key used.
 * @param lenK The length of the key.
 * @param message The message used.
 * @param lenM The length of the message.
 * @return The hashing of the key and message using HMAC as a byte array.
 */
unsigned char *hmac(unsigned char *key, int lenK, unsigned char *message, int lenM){
    int workingLen;
    unsigned long a, b, c;  // Output of tiger hash.

    unsigned char *iPad = ipad(lenK);
    unsigned char *xor = xorBytes(key, iPad, lenK);
    unsigned char *appended = appendBytes(xor, lenK, message, lenM);
    workingLen = lenK + lenM;
    unsigned long *padding = padInput(appended, &workingLen);
    tiger(&a, &b, &c, padding, workingLen);

    free(iPad); free(xor); free(padding);  // appended[] freed in padInput

    unsigned char *hashed = tigerToBytes(a, b, c);

    unsigned char *oPad = opad(lenK);
    xor = xorBytes(key, oPad, lenK);
    appended = appendBytes(xor, lenK, hashed, 24);
    workingLen = lenK + 24;
    padding = padInput(appended, &workingLen);
    tiger(&a, &b, &c, padding, workingLen);

    free(oPad); free(xor); free(padding); free(hashed);  // appended[] freed in padInput

    return tigerToBytes(a, b, c);;
}

int main(int argc, char **argv) {
    int lenKey, lenMessage;  // Get key and message.
    unsigned char *key = inputKey(&lenKey), *message = inputMessage(&lenMessage);

    unsigned char *hashed = hmac(key, lenKey, message, lenMessage);

    outputBytes(hashed, 24);

    free(key);
    free(message);
    free(hashed);
    return EXIT_SUCCESS;
}