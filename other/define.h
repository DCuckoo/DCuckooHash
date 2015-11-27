#ifndef DEFINE_H
#define DEFINE_H 

#include <stdio.h>
#include <iostream>
using namespace std;


typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned long long uint64;

#define MAX_RULES 10000
#define MAX_TRACES 100000

#define PORT_MAX			127

#define HIGHTBIT			2147483648					//Binary: 10000000000000000000000000000000

#define RULESET_LEN sizeof(struct ruleSet)


#define BF_ELE  512
#define BF_ELE_BIT 9
#define BF_HF   4

#define CONCAT(x, y) x ## y
#define SIMD_AND(x) CONCAT(SIMD_AND_,x)
#define SIMD_OR(x) CONCAT(SIMD_OR_,x)
#define SIMD_MOV(x) CONCAT(SIMD_MOV_,x)

#define DIR_SRC 0
#define DIR_DST 1

//#define TESTSPEED

//#define DEBUG





#endif