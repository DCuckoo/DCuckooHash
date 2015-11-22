/*a total of 18 hash functions*/
#ifndef HASH_FUNCTION_H
#define HASH_FUNCTION_H

typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned long long uint64;

unsigned int 
BOB(const unsigned char * str, unsigned int len);

unsigned int 
OAAT(const unsigned char * str, unsigned int len);

unsigned int 
Simple(const unsigned char * str, unsigned int len);

unsigned int 
SBOX(const unsigned char * str, unsigned int len);

//This is an integer hash function
unsigned int 
TWMX(unsigned int a);

unsigned int
Hsieh(const unsigned char * str, unsigned int len);

unsigned int 
RSHash(const unsigned char * str, unsigned int len);

unsigned int 
JSHash(const unsigned char * str, unsigned int len);

unsigned int 
BKDR(const unsigned char * str, unsigned int len);

unsigned int 
DJBHash (const unsigned char * str, unsigned int len);

unsigned int 
DEKHash(const unsigned char * str, unsigned int len);   

unsigned int
APHash(const unsigned char *str, unsigned int len);

unsigned int 
CRC32(const unsigned char * str,unsigned int len);

unsigned int
SDBM(const unsigned char * str, unsigned int len);

unsigned int
OCaml(const unsigned char *str, unsigned int len);

unsigned int
SML(const unsigned char *str, unsigned int len);

unsigned int
STL(const unsigned char *str, unsigned int len);

unsigned int
FNV32(const unsigned char *str, unsigned int len);

unsigned int
PJWHash (const unsigned char *str, unsigned int len);

unsigned int
MD5(const unsigned char *str, unsigned int len);

unsigned int
SHA1(const unsigned char *str, unsigned int len);


////////////////
unsigned int 
BOB1(const unsigned char * str, unsigned int len);
unsigned int 
BOB2(const unsigned char * str, unsigned int len);
unsigned int 
BOB3(const unsigned char * str, unsigned int len);
unsigned int 
BOB4(const unsigned char * str, unsigned int len);
unsigned int 
BOB5(const unsigned char * str, unsigned int len);
unsigned int 
BOB6(const unsigned char * str, unsigned int len);
unsigned int 
BOB7(const unsigned char * str, unsigned int len);
unsigned int 
BOB8(const unsigned char * str, unsigned int len);
unsigned int 
BOB9(const unsigned char * str, unsigned int len);
unsigned int 
BOB10(const unsigned char * str, unsigned int len);
unsigned int 
	BOB11(const unsigned char * str, unsigned int len);
unsigned int 
	BOB12(const unsigned char * str, unsigned int len);
unsigned int 
	BOB13(const unsigned char * str, unsigned int len);
unsigned int 
	BOB14(const unsigned char * str, unsigned int len);
unsigned int 
	BOB15(const unsigned char * str, unsigned int len);
unsigned int 
	BOB16(const unsigned char * str, unsigned int len);
uint64 
	BOB64(const unsigned char * str, unsigned int len);

#endif