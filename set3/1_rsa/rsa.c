/**
 * File :           rsa.c
 * Date :           7 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        1st exercise of Lab 3 for the course Information Security
 * Description :    This codes finds the rsa private key from the public key (& primes p, q) also encrypts and decrypt
 *                  messages using the rsa method.
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * This function finds n = x^p % m. For large p and m values.
 * @param base The x value.
 * @param power The p value.
 * @param modulo The m value.
 * @return (base ^ power) % modulo.
 */
long modPower(long base, long power, long modulo){
    long c = 1;
    while (power){
        if (power % 2){
            c = (c * base) % modulo;
            power--;
        } else {
            base = (base * base) % modulo;
            power /= 2;
        }
    }
    return c;
}

/**
 * This function finds the modular multiplicative inverse of e using the extend euclidean algorithm.
 * @param p The first prime p.
 * @param q The second prime q.
 * @param e The public key e.
 * @return The private key d. Such that x * e = 1 - d * (p - 1) * (q - 1) for some integer x.
 */
long findPrivateKey(long p, long q, long e){
    long totient = (p - 1) * (q - 1);
    long a = totient, b = e, r;  // values used in the standard euclidean algorithm.
    long c = totient, d = 1, s;  // values used in the extended euclidean algorithm.

    while (b){
        r = a % b;
        s = c - a/b * d;
        a = b;
        b = r;
        c = d;
        d = s;
    }

    while (c < 0) {
        c += totient;
    }
    return c;
}

/**
 * This function encrypts a message using rsa.
 * @param num The message as a number (num < n).
 * @param e The value e which is the first part of the public key.
 * @param n The value n which is the second part of the public key.
 * @return The encrypted message as a number.
 */
long rsaEncrypt(long num, long e, long n){
    return modPower(num, e, n);
}

/**
 * This function decrypts a cipher message using rsa.
 * @param num The cipher message as a number (num < n).
 * @param d The value d that is the private key.
 * @param n The value n that is part of the public key.
 * @return The decrypted message as a number.
 */
long rsaDecrypt(long num, long d, long n){
    return modPower(num, d, n);
}

int main(int argc, char **argv){
    char query;
    scanf("%c", &query);

    long p, q, e;
    scanf("%ld %ld %ld\n", &p, &q, &e);
    long d, n = p * q;

    if (query == 'd') d = findPrivateKey(p, q, e);

    long num;
    while (scanf("%ld\n", &num) == 1) {
        printf("%ld\n", (query == 'e') ? rsaEncrypt(num, e, n): rsaDecrypt(num, d, n));
    }

    return EXIT_SUCCESS;
}