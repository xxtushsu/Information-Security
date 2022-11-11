/**
 * File :           vigenere.c
 * Date :           24 sep, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        3nd exercise of Lab 1 for the course Information Security
 * Description :    The code encrypts and decrypts plain text using Vigenere cipher
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define ALPHA_LEN 26

/**
 * This function applies the modulo operator on number with the length of the english alphabet.
 * @param x The number that is operated on.
 * @return The result of x mod 26.
 */
int modAlpha(int x){
    while (x < 0){
        x += ALPHA_LEN;
    }
    return x % ALPHA_LEN;
}

/**
 * This function encrypts a text using Vigenere cipher.
 * @param key The key to encrypt with.
 * @param text The text to be encrypted.
 */
void encrypt (char *key, char *text){
    int i = 0, j = 0;
    while (text[i] != '\0') {
        if (key[j] == '\0') j = 0;
        int shift = key[j] - 'a';

        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = (char) (modAlpha(text[i] - 'a' + shift) + 'a');
            j++;
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = (char) (modAlpha(text[i] - 'A' + shift) + 'A');
            j++;
        }

        i++;
    }
}

/**
 * This function decrypt a text using Vigenere cipher.
 * @param key The key to encrypt with.
 * @param text The text to be encrypted.
 */
void decrypt (char *key, char *text){
    int i = 0, j = 0;
    while (text[i] != '\0') {
        if (key[j] == '\0') j = 0;
        int shift = 'a' - key[j];

        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = (char) (modAlpha(text[i] - 'a' + shift) + 'a');
            j++;
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = (char) (modAlpha(text[i] - 'A' + shift) + 'A');
            j++;
        }

        i++;
    }
}

/**
 * This is function reads the input from stdin until it comes across a specific character.
 * @param exit The character at which to stop reading.
 * @return The input scanned as a string.
 */
char *readUntil(int exit){
    int c = getchar(), i = 0, len = 2;
    char *text = malloc(sizeof(char) * len);

    while (c != exit){
        text[i] = (char) c;
        i++;
        if (i == len){
            len *= 2;
            text = realloc(text, sizeof(char)*len);
        }
        c = getchar();
    }
    text[i] = '\0';
    return text;
}

int main(int argc, char **argv){
    char *flag = readUntil(' ');
    char *key = readUntil('\n');  // read the key in the first line.
    char *text = readUntil(EOF);  // read text to perform queries on

    if (!strcmp(flag, "e")){
        encrypt(key, text);
    } else if (!strcmp(flag, "d")){
        decrypt(key, text);
    } else {
        printf("Error unexpected input format\n");
        exit(66);
    }


    printf("%s", text);
    free(text);
    free(key);
    return EXIT_SUCCESS;
}
