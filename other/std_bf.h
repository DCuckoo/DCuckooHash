#ifndef STD_BF
#define STD_BF 

#include "hash_function.h"
//#include <cstring>
#include <iostream>
#include "define.h"
#include "key-value.h"

#define HASH_NUM_MAX 16
//#define STATISTIC
using namespace std;


static uint (* hash_func[HASH_NUM_MAX])(const unsigned char * str, uint len) = 
{BOB1, JSHash, OCaml, OAAT, PJWHash, RSHash,  SDBM, Simple, SML, STL,
APHash, BKDR, DEKHash, DJBHash, FNV32, Hsieh};

class StandardBF 
{
private:
	uchar * bf_base; //bloom filter base

	unsigned int bf_m; //bloom filter length
	unsigned int bf_k; //hash function numbers;
	unsigned int bf_n; //# of elements inserted

	//pointers to hash function
	unsigned int (*bf_hfp[18])(const unsigned char * str, unsigned int len);

public:	
	StandardBF(unsigned int m, unsigned int k)
	{
		
		if(k > 18){
			cerr << "the # of hash functions cannot exceed 18" << endl;
		}
		bf_m = m;
		bf_k = k;
		bf_n = 0;
		QuerymemAccNum=0;
		bf_base = new uchar [(bf_m>>3)+1];
		memset(bf_base, 0, (bf_m>>3)+1);

		

		uint (* tmp_ptr[HASH_NUM_MAX])(const unsigned char * str, uint len) = 
		{BOB1,BOB2,BOB3,BOB4,BOB5,BOB6,BOB7,BOB8,
		 BOB9,BOB10,BOB11,BOB12,BOB13,BOB14,BOB15,BOB16};

		for(int i = 0; i < HASH_NUM_MAX; i++){
			bf_hfp[i] = tmp_ptr[i];
		}
	
	}
	StandardBF(){
		bf_m = 0;
		bf_k = 0;
		bf_n = 0;
		QuerymemAccNum=0;
		bf_base = NULL;
		uint (* tmp_ptr[HASH_NUM_MAX])(const unsigned char * str, uint len) = 
		{BOB1,BOB2,BOB3,BOB4,BOB5,BOB6,BOB7,BOB8,
		BOB9,BOB10,BOB11,BOB12,BOB13,BOB14,BOB15,BOB16};
		for(int i = 0; i < HASH_NUM_MAX; i++){
			bf_hfp[i] = tmp_ptr[i];
		}
	}
	~StandardBF()
	{
		delete [] bf_base;
	}
	void initial(unsigned int m, unsigned int k){
		if(k > 18){
			cerr << "the # of hash functions cannot exceed 17" << endl;
		}
		bf_m = m;
		bf_k = k;
		bf_n = 0;
		QuerymemAccNum=0;
		bf_base = new uchar [(bf_m>>3)+1];
		memset(bf_base, 0, (bf_m>>3)+1);
	}
	void reset(){
		memset(bf_base, 0, bf_m);
	}
	unsigned int insert(const unsigned char * str, unsigned int len){
		unsigned int value;
		for(uint i = 0; i < bf_k; i++){
			value = bf_hfp[i](str, len) % bf_m;
			bf_base[value>>3] |= (128 >> (value%8));
		}
		bf_n ++;
		return 1;
	}
	unsigned int query(const unsigned char * str, unsigned int len){
		register unsigned int value;
		for(register uint i = 0; i < bf_k; i++){
			value = bf_hfp[i](str, len) % bf_m;
#ifdef STATISTIC
			QuerymemAccNum++;
#endif // STATISTIC
			if(0== (bf_base[value>>3] & (128 >> (value%8))))return 0;
		}
		return 1;
	}

	uint Get_bf_m(){return bf_m;}
	uint Get_bf_k(){return bf_k;}
	uint Get_bf_n(){return bf_n;}

	uint QuerymemAccNum;
};


class multibitBF 
{
private:
	uint   bf_m;    //bloom filter length
	uint   bf_k;    //hash function numbers;
	uint   bf_n;    //# of elements inserted
	uchar* bf_base; //bloom filter base
	uint   (*bf_hash[18])(const unsigned char * str, unsigned int len);

public: //experimental parameters
	uint QuerymemAccNum;

public:	
	multibitBF(unsigned int m, unsigned int k)
	{
		if(k > 18)cerr << "the # of hash functions cannot exceed 18" << endl;
		bf_m = m;
		bf_k = k;
		bf_n = 0;
		QuerymemAccNum=0;
		bf_base = new uchar[bf_m];
		memset(bf_base, 0, bf_m);

		uint (* tmp_ptr[HASH_NUM_MAX])(const unsigned char * str, uint len) = 
		{BOB1,BOB2,BOB3,BOB4,BOB5,BOB6,BOB7,BOB8, BOB9,BOB10,BOB11,BOB12,BOB13,BOB14,BOB15,BOB16};

		for(int i = 0; i < HASH_NUM_MAX; i++)bf_hash[i] = tmp_ptr[i];
	}
	~multibitBF()
	{
		delete [] bf_base;
	}
	void setiBit(int pos, int iBF)
	{
		bf_base[pos] |=  (1<<(8-iBF));
	}
	void insert(const unsigned char * str, unsigned int len, int iBF)
	{
		for(uint i = 0; i < bf_k; i++, bf_n++)
		{
			unsigned int pos = bf_hash[i](str, len) % bf_m;
			setiBit(pos,iBF);
		}
	}
	uchar query(const unsigned char * str, unsigned int len)
	{	
		uchar ret=0xFF;
		for(register uint i = 0; i < bf_k && ret; i++)
		{
#ifdef STATISTIC  
			QuerymemAccNum++;  
#endif
			ret &= bf_base[bf_hash[i](str,len)%bf_m];
		}
		return ret;
	}
};
#endif