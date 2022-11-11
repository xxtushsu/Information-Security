/**
 * File :           validation.c
 * Date :           2 Oct, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        4th exercise of Lab 2 for the course Information Security
 * Description :    The code check if public and private key is valid
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * This function reads an array of positive integers from stdin.
 * @param exit The character at which the array should now longer be read.
 * @param len A pointer to the length of the array to update.
 * @return An allocated array of positive integers.
 */
int *readUntil(int exit, int *len){
    int c = getchar(), i = 0, sign=1;
    *len = 2;
    int *array = malloc(sizeof(int) * (*len));
    array[0]=0;

    while (c != exit){
        if (c == '-'){
            sign = -1;
        }
        if (c >='0' && c<='9') {
            array[i] = (array[i] * 10) + (c - '0')*sign;
        }
        if (c == ' ') {
            i++;
            if (i == *len){
                *len *= 2;
                array = realloc(array, sizeof(int)*(*len));
            }
            array[i]=0;
            sign = 1;
        }
        c = getchar();
    }
    *len = i+1;
    return array;
}

/**
 * This function finds the greatest common divisor of two number m & n.
 * @return gcd(m,n)
 */
int gcd (int m, int n) {
    int r;
    while (m != 0) {
        r = n % m;
        n = m;
        m = r;
    }
    return n;
}

/**
 * This function checks if a set of private keys and public keys are valid for knapsack encryption.
 * @param m A value m for the private key.
 * @param n A value n for the private key.
 * @param private The private key as an array of integers.
 * @param public The public key as an array of integers.
 * @param privateLength The private key length.
 * @param publicLength The public key length.
 * @return 1 if the both private and public are valid, 0 if only private is value and -1 otherwise.
 */
int validation (int m, int n, int *private, int *public, int privateLength, int publicLength) {
    int i, sum = 0;

    if (gcd(m, n) != 1) {  // Check that the m and n are relatively prime.
        return -1;
    }

    for(i=0; i<privateLength; i++){ // Check that all values in private key are positive.
        if (private[i]<0){
            return -1;
        }
    }

    for (i = 0; i < privateLength - 1; i++) {  // Check that the private key is super increasing.
        sum += private[i];
        if (sum >= private[i + 1]) {
            return -1;
        }
    }

    if (n <= sum + private[privateLength-1]){  // Check that n is larger than the sum of all values in the private key.
        return -1;
    }

    if (privateLength != publicLength){  // Check that the private key and public key have the same length.
        return 0;
    }

    for (i = 0; i < publicLength; i++) {  // Check if two public key is properly computed.
        if ((private[i] * m) % n != public[i]) {
            return 0;
        }
    }

    return 1;   // All checks passed both keys are valid.
}

int main(int argc, char **argv) {
    int m, n,privateLength, publicLength;
    scanf("%d %d\n",&m, &n);
    int *privateKey = readUntil('\n',&privateLength);
    int *publicKey = readUntil(EOF,&publicLength);

    printf("%d\n",validation(m,n,privateKey,publicKey,privateLength,publicLength));
    free(privateKey);
    free(publicKey);
    return 0;
}