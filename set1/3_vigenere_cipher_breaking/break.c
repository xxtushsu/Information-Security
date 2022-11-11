/**
 * File :           break.c
 * Date :           25 sep, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        4th exercise of Lab 1 for the course Information Security
 * Description :    This code attacks an encrypted text that used the Vigenere cipher.
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

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
 * This function gets the average of an array.
 * @param arr An array of integers.
 * @param len The length of the array.
 * @return The mean value of the array as a double.
 */
double average(int *arr, int len){
    double sum = 0;
    for (int i = 0; i < len; i++){
        sum += (double) arr[i];
    }
    return sum / (double) len;
}

/**
 * This function gets the standard deviation of an array.
 * @param arr An array of integers.
 * @param len The length of the array.
 * @return The standard deviation of the array as a double.
 */
double std(int *arr, int len){
    double a = average(arr, len), sum = 0.0;
    for (int i = 0; i < len; i++){
        sum += (double) (arr[i] * arr[i]);
    }
    return sqrt(sum / (double) (len) - a * a);
}

/**
 * This is function rea s the input from stdin until it comes across a specific character.
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

/**
 * This function gets the frequency vectors for a key size.
 * @param text The text to get the frequency vectors from.
 * @param keyLen Key length k.
 * @return Array of k frequency vectors vs. Where v: v[0] = count(A), v[1] = count(B) ... v[26] = count(Z).
 */
int **getFrequencyVectors(char *text, int keyLen){
    int **frequencies = malloc(keyLen * sizeof(int*));
    for (int i = 0; i < keyLen; i++) frequencies[i] = calloc(ALPHA_LEN, sizeof(int));

    int i = 0, j = 0;
    while (text[i] != '\0'){
        char c = text[i];
        if ('a' <= c && c <= 'z') {
            frequencies[j % keyLen][c - 'a']++;
            j++;
        } else if ('A' <= c && c <= 'Z') {
            frequencies[j % keyLen][c - 'A']++;
            j++;
        }
        i++;
    }
    return frequencies;
}

/**
 * This function finds the most likely key length between minLen and maxLen.
 * @param minLen The min key length to check.
 * @param maxLen The max key length to check.
 * @param text The text that was encoded using the key.
 * @return The most likely key length.
 */
int likelyKeyLen(int minLen, int maxLen, char *text){
    int likelyLen = 0;
    double likelihood = 0.0;

    for (int keyLen = minLen; keyLen <= maxLen; keyLen++){
        double sum = 0.0;

        int **frequencyVectors = getFrequencyVectors(text, keyLen);
        for (int i = 0; i < keyLen; i++){
            sum += std(frequencyVectors[i], ALPHA_LEN);
            free(frequencyVectors[i]);
        }
        free(frequencyVectors);

        printf("The sum of %d std. devs: %0.2f\n", keyLen, sum);
        if (sum > likelihood){
            likelihood = sum;
            likelyLen = keyLen;
        }
    }

    return likelyLen;
}

/**
 * Gets the index of the max value in an array.
 * @param arr The array of integers.
 * @param len The length of this array.
 * @return The index of the max value in the given array.
 */
int getMaxIndex(int *arr, int len) {
    int maxIndex = 0;
    for (int i = 0; i < len; i++){
        if (arr[i] > arr[maxIndex]){
            maxIndex = i;
        }
    }
    return maxIndex;
}
/**
 * This function finds the most likely key given a key length.
 * @param text A text that was encoded with the key.
 * @param keyLen The length of the key.
 * @return The key as a string.
 */
char *getLikelyKey(char *text, int keyLen){
    int **frequencyVectors = getFrequencyVectors(text, keyLen);
    char *key = malloc((keyLen+1) * sizeof(char));

    for (int i = 0; i < keyLen; i++){
        key[i] = (char) (modAlpha(getMaxIndex(frequencyVectors[i], ALPHA_LEN) + 'a' - 'e') + 'a');
        free(frequencyVectors[i]);
    }

    free(frequencyVectors);
    key[keyLen] = '\0';
    return key;
}

int main(int argc, char **argv){
    int min, max;
    scanf("%d\n%d", &min, &max);
    char *text = readUntil(EOF);

    int len = likelyKeyLen(min, max, text);
    char *key = getLikelyKey(text, len);
    printf("\nKey guess:\n%s\n", key);
    free(key);

    return EXIT_SUCCESS;
}