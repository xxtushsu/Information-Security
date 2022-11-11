/**
 * File :           vernam.c
 * Date :           1 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        1st exercise of Lab 2 for the course Information Security
 * Description :    This code encodes a input of bytes with a key using verman, one time padding cipher.
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * This function reads byte input from stdin until a byte code is read and returns it in a byte array.
 * @param exit The byte code that should terminate the reading of the input when it is read.
 * @param size A pointer to the size of the byte array that is returned.
 * @return An allocated array of bytes.
 */
unsigned char *inputUntil(unsigned char exit, int *size){
    int bytesRead = 0;
    *size = 2;
    unsigned char c, *byteArr = malloc(sizeof(unsigned char) * *size);
    c = getc(stdin);

    while (c != exit){
        byteArr[bytesRead] = c;
        bytesRead++;
        if (bytesRead == *size){
            *size *= 2;
            byteArr = realloc(byteArr, sizeof(unsigned char) * *size);
        }
        c = getc(stdin);
    }

    *size = bytesRead;
    return byteArr;
}

/**
 * This function reads byte input from stdin of a given size.
 * @param size The number of bytes that should be read.
 * @return The input read as a byte array.
 */
unsigned char *input(int size){
    unsigned char *byteArr = malloc(sizeof(unsigned char) * size);
    for (int i = 0; i < size; i++){
        byteArr[i] = getc(stdin);
    }
    return byteArr;
}

/**
 * This function outputs an array of bytes into stdout.
 * @param byteArr The byte array that should be outputted.
 * @param size The length of the byte array.
 */
void output(unsigned char *byteArr, int size){
    for (int i = 0; i < size; i++){
        putc(byteArr[i], stdout);
    }
}

/**
 * This function encodes a text using a given key by the vernam method.
 * @param key The key that is used to encode the text in bytes.
 * @param text The text that should be encoded in bytes.
 * @param size The length of the key and the text.
 */
void vernam(unsigned char *key, unsigned char *text, int size){
    for (int i = 0; i < size; i++){
        text[i] = key[i] ^ text[i];
    }
}

int main(int argc, char **argv) {
    int size;
    unsigned char *key = inputUntil(0xFF, &size), *text = input(size);

    vernam(key, text, size);
    output(text, size);

    free(key);
    free(text);
    return EXIT_SUCCESS;
}