/**
 * File :           knapsack.c
 * Date :           2 Oct, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        5th exercise of Lab 2 for the course Information Security
 * Description :    The code encrypt and/or decrypt the input
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * This function reads a single number from stdin until it reads a space or newline.
 * @param num A pointer to the number that should be updated.
 * @param split The expected char at the end of the number.
 * @return 1 if success 0 otherwise.
 */
int readNumber(int *num, char split){
    int sign = 1;
    char c = (char) getchar();
    *num = 0;

    if (c == '-') {
        sign = -1;
        c = (char) getchar();
    }

    if (!(c >='0' && c<='9') && c != split) return 0;

    while (c != split){
        if (c >='0' && c<='9') {
            *num = (*num * 10) + (c - '0') * sign;
        } else {
            return 0;
        }
        c = (char) getchar();
    }

    return 1;
}

/**
 * This function reads an array of positive integers from stdin.
 * @param exit The character at which the array should now longer be read.
 * @param len A pointer to the length of the array to update.
 * @return An allocated array of positive integers.
 */
int *readArray(char exit, int *len){
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
 * This function encrypts a series of number from stdin using knapsack and a given key.
 * @param key The key as an array of int, used to encode.
 * @param len The length of the key.
 */
void encrypt (int *key, int len) {
    unsigned int num;

    while (readNumber(&num, '\n')){
        unsigned int x = 1;
        int sum = 0;

        for (int j = 0; j < len; j++) {
            sum += key[j] * ((num & x) != 0);
            x *= 2;
        }

        printf("%d\n",sum);
    }
}

/**
 * This function encrypts a series of number from stdin using knapsack and a given key.
 * @param m The private value m used as part of the private key for decryption
 * @param n The private value n used as part of the private key for decryption.
 * @param key The key as an array of int, used to encode.
 * @param len The length of the key.
 */
void  decrypt (int m, int n, int *key, int len){
    int rev=1;  // Find the reverse of the multiplier m.
    while ((m*rev)%n != 1){
        rev++;
    }

    unsigned int num;
    while (readNumber(&num, '\n')){
        int sum = 0;
        num = (num*rev)%n;

        // Solve knapsack problem greedily.
        for (int j= len - 1; j >= 0; j--){
            if (key[j] <= num){
                sum += 1;
                num -= key[j];
            }
            sum *= 2;
        }

        printf("%d\n",sum/2);
    }
}

int main(int argc, char **argv) {
    int *key, len;
    char c;
    scanf("%c\n",&c);

    if (c =='e'){
        key = readArray('\n', &len);
        encrypt(key, len);
    } else {   // c = 'd'
        int m, n;
        scanf("%d %d\n",&m,&n);
        key = readArray('\n', &len);
        decrypt(m, n, key, len);
    }

    free(key);
    return 0;
}