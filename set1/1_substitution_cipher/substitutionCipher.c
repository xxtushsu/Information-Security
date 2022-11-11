/**
 * File :           substitutionCipher.c
 * Date :           23 sep, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        2nd exercise of Lab 1 for the course Information Security
 * Description :    The code performs a series of substitution queries on a text.
 */
#include <stdio.h>
#include <stdlib.h>

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
 * This function encrypts a text with a shift.
 * @param x The shift used to encrypt.
 * @param text The text to be encrypted.
 */
void es (int x, char *text){
    int i = 0;
    while (text[i] != '\0') {
        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = (char) (modAlpha(text[i] - 'a' + x) + 'a');
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = (char) (modAlpha(text[i] - 'A' + x) + 'A');
        }
        i++;
    }
}

/**
 * This function encrypts a text with mapping to a different alphabet.
 * @param map The mapping the text should be encrypted to.
 * @param text The text to be encrypted.
 */
void em(char *map, char *text){
    int i = 0;
    while (text[i] != '\0') {
        if ('a' <= text[i] && text[i] <= 'z'){
            text[i] = map[text[i] - 'a'];
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = map[text[i] - 'A'] - 'a' + 'A';
        }
        i++;
    }
}

/**
 * This function decrypts a text with the mapping that was used to encrypt it.
 * @param map The mapping.
 * @param text The text that should be decrypted.
 */
void dm(char *map, char *text){
    // modify mapping to be reverse
    char *reverseMap = malloc(sizeof(char)*ALPHA_LEN);
    for (int i = 0; i < ALPHA_LEN; i++){
        reverseMap[map[i]-'a'] = (char) ('a' + i);
    }
    em(reverseMap, text);
    free(reverseMap);
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
    char *queries = readUntil('\n');  // read the queries in the first line.
    char *text = readUntil(EOF);  // read text to perform queries on

    // keep track of the mapping of the alphabet to apply to the text at the end
    char alpha[ALPHA_LEN] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    // keep track of the shift to apply to the alphabet before applying to text
    int shift = 0;

    int i = 0;
    while (queries[i] != '\0') {  // Iterate over first line to perform queries
        char c, *map = malloc(sizeof(char)*ALPHA_LEN);

        sscanf(queries + i, "%c", &c);
        i += 2;

        if (('0' <= queries[i] && queries[i] <= '9') || '-' == queries[i]){
            int x;
            sscanf(queries + i, "%d", &x);
            if (c == 'e') {
                shift += modAlpha(x);
            } else {
                shift -= modAlpha(x);
            }
        } else {
            sscanf(queries + i, "%s", map);
            es(shift, alpha);
            shift = 0;
            if (c == 'e'){
                em(map, alpha);
            } else {
                dm(map, alpha);
            }
        }
        free(map);

        while (('a' <= queries[i] && queries[i] <= 'z') || ('0' <= queries[i] && queries[i] <= '9') || queries[i] == '-') {
            i++;
        }
        if (queries[i] == ' '){
            i++;
        }

    }
    free(queries);

    es(shift, alpha);
    em(alpha, text);
    printf("%s", text);
    free(text);
    return EXIT_SUCCESS;
}

