/**
 * File :           feistel.c
 * Date :           2 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        3rd exercise of Lab 2 for the course Information Security
 * Description :    This code encodes a byte input composed of multiple blocks using a key by the feistel cipher method.
 */

#include <stdio.h>
#include <stdlib.h>

#define BLOCK_SIZE 8  // The number of byte in a block.
#define SUB_KEY_SIZE 4  // The number of byte in a sub-key.

/**
 * This function swaps two pointers to byte arrays.
 * @param a A pointer to the first byte array.
 * @param b A point to the second byte array.
 */
void swap(unsigned char **a, unsigned char **b){
    unsigned char *temp = *a;
    *a = *b;
    *b = temp;
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
 * This function reads bytes input from stdin until the end of stdin and returns the bytes read as an array.
 * @param size A pointer to the size of the byte array that is returned.
 * @return An allocated array of bytes.
 */
unsigned char *inputRest(int *size){
    int bytesRead = 0;
    *size = 2;
    unsigned char c, *byteArr = malloc(sizeof(unsigned char) * *size);
    c = getc(stdin);

    while (!feof(stdin)){
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
 * This function applies feistel cipher on a block of bytes split into to byte arrays left and right.
 * @param key The key made up of multiple sub-keys that is used to encrypt the block of bytes.
 * @param keyLen The length of the key with is a multiple of 4.
 * @param left The 4 left bytes of the block as a byte array.
 * @param right The 4 right bytes of the block as a byte array.
 */
void feistel(unsigned char *key, int keyLen, unsigned char **left, unsigned char **right){
    for (int j = 0; j < keyLen; j += SUB_KEY_SIZE){
        unsigned char *subKey = &key[j];

        for (int k = 0; k < SUB_KEY_SIZE; k++){
            (*left)[k] = (*left)[k] ^ subKey[k];
        }

        swap(right, left);
    }
}

/**
 * This function encrypts a text using feistel given a key.
 * @param key The key containing multiple sub keys.
 * @param keyLen The key length being a multiple of 4.
 * @param text The text that should be encrypted.
 * @param textLen The text length being a multiple of 8.
 */
void feistelEncrypt(unsigned char *key, int keyLen, unsigned char *text, int textLen){
    for (int i = 0; i < textLen; i += BLOCK_SIZE){
        unsigned char *left = &text[i];
        unsigned char *right = &text[i + BLOCK_SIZE / 2];

        feistel(key, keyLen, &left, &right);

        // Make sure the left and right sides are in the correct positions.
        for (int k = 0; k < BLOCK_SIZE/2; k++){
            unsigned char temp = right[k];
            text[i+k] = left[k];
            text[i+k+BLOCK_SIZE/2] = temp;
        }
    }
}

/**
 * This function decrypts a text using feistel given a key.
 * @param key The key containing multiple sub keys.
 * @param keyLen The key length being a multiple of 4.
 * @param text The text that should be decrypted.
 * @param textLen The text length being a multiple of 8.
 */
void feistelDecrypt(unsigned char *key, int keyLen, unsigned char *text, int textLen){
    // flip key so that sub-keys are processed in inverse order.
    for (int i = 0; i < keyLen/2 - SUB_KEY_SIZE/2; i += SUB_KEY_SIZE){
        for (int j = 0; j < SUB_KEY_SIZE; j++){
            unsigned char temp = key[i + j];
            key[i + j] = key[keyLen - SUB_KEY_SIZE - i + j];
            key[keyLen - SUB_KEY_SIZE - i + j] = temp;
        }
    }

    // now decrypt = encrypt (plus some swapping)
    for (int i = 0; i < textLen; i += BLOCK_SIZE){
        unsigned char *left = &text[i];
        unsigned char *right = &text[i + BLOCK_SIZE / 2];

        swap(&left, &right);
        feistel(key, keyLen, &left, &right);
        swap(&left, &right);

        // Make sure the left and right sides are in the correct positions.
        for (int k = 0; k < BLOCK_SIZE/2; k++){
            unsigned char temp = right[k];
            text[i+k] = left[k];
            text[i+k+BLOCK_SIZE/2] = temp;
        }
    }
}

int main(int argc, char **argv) {
    unsigned char query = getc(stdin);
    getc(stdin);  // Remove 0xFF

    int keyLen, textLen;
    unsigned char *key = inputUntil(0xFF, &keyLen), *text = inputRest(&textLen);

    if (query == 0x65){
        // 'e'
        feistelEncrypt(key, keyLen, text, textLen);
    } else {
        // 'd'
        feistelDecrypt(key, keyLen, text, textLen);
    }

    output(text, textLen);

    free(text);
    free(key);
    return EXIT_SUCCESS;
}