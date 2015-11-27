#pragma once


#include "key-value.h"
#include "std_bf.h"
#include <stdio.h>

#define KEYLENGTH 19 //include char \0



class PeacockHash
{
public:
	PeacockHash(void);
	/*
	len_main: length of main hash table
	r: ratio factor, which  is ratio of the size of hash table i and  that of hash table i+1;
	stage: number of stages
	*/
	
	PeacockHash( unsigned int len_main, unsigned int r , unsigned int stage );
	/*
	elementNum: Number of elements
	ht_times: the ratio of total size of hash tables to total number of elements
	Nstages_p: number of stages in PeacockHash. default parameter is 8
	*/
	PeacockHash( unsigned int elementNum, float ht_times, unsigned int Nstages_p );
	/*
	initial hash table using entries from InputFile
	*/
	bool initialFromFile(char *InputFileName, float ht_times , unsigned int stage = 8);
	/*
	key: a key to insert
	val: the corresponding value of key
	if insert successfully, this function will return true, 
	else it will return false;
	stage: Number of stages. Default parameter is 8.
	*/
	bool insert(char * key , int val);
	bool search(const unsigned char *key, int & val);  //search for a key, but return its value in the hash table
	bool remove(char *key); //remove a key from hash table
	void collect(void); //collect informations about loading factor
	/* report 
	loading factor , number of collisions and the ratio of the number
	of collsions to the total size of hash tables */
	void report(char *file); 
	bool reset();
	bool test(char *File);

	~PeacockHash(void);

public:
	unsigned int totsize; //total size of hash table
	unsigned int *hashlen; // an array contains the size of every hash table

	hashentry * MainHashTab; //main hash table
	hashentryP **SubHashTab; //sub hash tables
	StandardBF *BloomFilter; //BloomFilters

	unsigned int NumCollisions;
	float *loadingfactor; //loading factor of each table
	float loadingfactorT; //loading factor of total hash tables
	unsigned int ratiofactor; //ratio factor
	unsigned int NumStages ; // number of stages

	unsigned int ** NumSigLikedChain; //length of singly linked chain in sub hash tables 
	
	//Count for search insert and remove operation
	unsigned int searchCount;
	unsigned int insertCount;
	unsigned int removeCount;

	//XXXMemAcc is a array contains the average memory access times over 100 operations of XXX
	float  searchMemAcc[MEMORY_ACC_POINTER_MAX];
	float  removeMemAcc[MEMORY_ACC_POINTER_MAX];
	float  insertMemAcc[MEMORY_ACC_POINTER_MAX];

	//XXXMAcurpos is a integer represents the index of the leftmost unused slot in XXXMemAcc
	unsigned int searchMAcurpos;
	unsigned int insertMAcurpos;
	unsigned int removeMAcurpos;
	
	//XXXMAtot is a temporal variable represents the sum of  Memory access times before, which will be reset after MEMORY_ACC_UNIT times operations
	unsigned int searchMAtot;
	unsigned int insertMAtot;
	unsigned int removeMAtot;

};

/*
	Generate N*1000 access requests, and output average and max memory access times to file "statfile"
	*/
//void GenerateAccess(PeacockHash* peahash, int N, char *statfile); //Unit: 1000