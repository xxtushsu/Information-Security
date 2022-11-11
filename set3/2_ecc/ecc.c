/**
 * File :           ecc.c
 * Date :           7 okt, 2020
 * Authors :        Antonin (s3791378), Xiaoyu (s3542807)
 * Context :        2nd exercise of Lab 3 for the course Information Security
 * Description :    This codes does diffie-Hellman Elliptic curve cryptography.
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * This function is a modulo function that works for negative numbers.
 * @return The smallest value x such that x = a (mod b).
 */
long mod(long a, long b){
    while (a < 0) a += b;
    return a % b;
}

/**
 * This function finds the multiplicative inverse of a value x (% modulo).
 * @param x The value x.
 * @param modulo The modulo for which the inverse should be found.
 * @return A value i such that i * x = 1 (% modulo).
 */
long inverse(long x, long modulo){
    for (long i = 1; i < modulo; i++){
        if (mod(i * x, modulo) == 1) return i;
    }
    printf("Error no inverse found!\n");
    exit(99);
}

/**
 * Simple 2D point struct.
 */
struct Point {
    long x;
    long y;
    int isInfinity;
};

/**
 * This function initializes a point to x and y coordinates.
 * @return A new point at x, y.
 */
struct Point initPoint(long x, long y){
    struct Point p;
    p.x = x;
    p.y = y;
    p.isInfinity = 0;
    return p;
}

/**
 * This function initializes a infinite point.
 * @return A new point flagged as infinite.
 */
struct Point infPoint(){
    struct Point p;
    p.isInfinity = 1;
    return p;
}

/**
 * This function adds two points on an elliptic curve together. Elliptic curve: y^3 = x^2 + ax + b (% modulo).
 * @param a The constant a of the elliptic curve.
 * @param b The constant b of the elliptic curve.
 * @param modulo The constant modulo of the elliptic curve.
 * @param p1 The first point.
 * @param p2 The second point.
 * @return p1 + p2.
 */
struct Point addPoints(long a, long b, long modulo, struct Point p1, struct Point p2){
    long x3, y3, m;

    if (p1.isInfinity) return p2;
    if (p2.isInfinity) return p1;

    if ((p1.x == p2.x) && (p1.y == p2.y)){
        if (!p1.y) return infPoint();
        m = mod((3 * p1.x * p1.x + a) * inverse(2 * p1.y, modulo), modulo);
    } else {
        if (!(p2.x - p1.x)) return infPoint();
        m = mod((p2.y - p1.y) * inverse(p2.x - p1.x, modulo), modulo);
    }

    x3 = mod(m * m - p1.x - p2.x, modulo);
    y3 = mod(m*(p1.x - x3) - p1.y, modulo);

    return initPoint(x3, y3);
}

/**
 * This function multiples a point on an elliptic curve y^3 = x^2 + ax + b (% modulo).
 * @param a The constant a of the elliptic curve.
 * @param b The constant b of the elliptic curve.
 * @param modulo The constant modulo of the elliptic curve.
 * @param p The point that should be multiplied.
 * @param m The amount of times m that point should be added to itself.
 * @return p*m on curve y^3 = x^2 + ax + b (% modulo).
 */
struct Point scalePoint(long a, long b, long modulo, struct Point p, long m){
    struct Point newP = infPoint();
     while (m){
        if (m % 2) newP = addPoints(a, b, modulo, p, newP);
        p = addPoints(a, b, modulo, p, p);  // double point p
        m /= 2;

        if (p.isInfinity) break;
    }
    return newP;
}

int main(int argc, char **argv){
    long x, y;
    long a, b, p;
    long m, n;

    scanf("(%ld, %ld)\n", &x, &y);
    scanf("%ld %ld %ld\n", &a, &b, &p);
    scanf("%ld %ld", &m, &n);

    struct Point sharedSecret = scalePoint(a, b, p, initPoint(x, y), m*n);
    printf("(%ld, %ld)\n", sharedSecret.x, sharedSecret.y);

    return EXIT_SUCCESS;
}