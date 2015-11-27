#pragma once

#include "key-value.h"
#include "std_bf.h"
#include <stdio.h>
#include <bitset>

#define NUM_HASH_FUNCTION_IN_BF 16
#define KEYLENGTH 19 //include char \0

#define STATE_KICK 0
#define	STATE_BLIND_KICK 1

#define MEMACCESS 100 // number of memory access to count

using namespace std;
class RTBHash
{
public:
	RTBHash(void);
	~RTBHash(void);

	/*
	Class constructor
	LenFirstHashTab: length of the Last hash table.
	comdiff: common difference of lengths of two successive hash tables
	stages: number of hash tables, which must be an even number and less than or equal to 16.
	*/
	RTBHash(unsigned int LenLastHashTab, unsigned int comdiff, unsigned int stages);
	/*
	elementNum: Number of elements
	ht_times: the ratio of total size of hash tables to total number of elements
	Nstages_p: number of stages in PeacockHash. default parameter is 8
	*/
	RTBHash( unsigned int elementNum, float ht_times, unsigned int Nstages_p );
	/*
	initial hash table using entries from InputFile
	*/
	bool initialFromFile(char *InputFileName, float ht_times, unsigned int Nstages_p = 8);
	/*
	key: a key to insert
	val: the corresponding value of key
	if insert successfully, this function will return true, 
	else it will return false;
	*/
	bool insert(char * key , int val);
	bool search(char *key, int & val);  //search for a key, but return its value in the hash table
	bool remove(char *key); //remove a key from hash table
	void collect(void); //collect informations about loading factor
	/* report 
	loading factor , number of collisions and the ratio of the number
	of collsions to the total size of hash tables */
	void report(char *file); 
	bool reset();
	bool test(char *File);


public:
	int blind_kick_num;
	unsigned int totsize; //total size of hash table
	unsigned int *hashlen; // an array contains the size of every hash table
	unsigned int grouplen; //length of a group
	
	hashentryP ** HashTab; //sub hash tables
	multibitBF * mulbitBF; //multibitBF 
	StandardBF * lowPartBF; //Standard BF for lower part
	bool ** bitsetGrpPtr;

	unsigned int Collisions_nokick;
	unsigned int NumCollisions;
	unsigned int * NumLoading; //Number of Loaded buckets in each hash table
	float *loadingfactor; //loading factor of each table
	float loadingfactorT; //loading factor of total hash tables
	unsigned int NumStages ; // number of stages
	unsigned int NumGroups ; //number of groups
	unsigned int * NumSigLikedChain; //length of singly linked chain in last hash table 
	
	//Count for search insert and remove operation
	unsigned int searchCount;
	unsigned int insertCount;
	unsigned int removeCount;

	//XXXMemAcc is a array contains the average memory access times over 100 operations of XXX
	float searchMemAcc[MEMORY_ACC_POINTER_MAX];
	float removeMemAcc[MEMORY_ACC_POINTER_MAX];
	float insertMemAcc[MEMORY_ACC_POINTER_MAX];

	//XXXMAcurpos is a integer represents the index of the leftmost unused slot in XXXMemAcc
	unsigned int searchMAcurpos;
	unsigned int insertMAcurpos;
	unsigned int removeMAcurpos;
	
	//XXXMAtot is a temporal variable represents the sum of  Memory access times before, which will be reset after MEMORY_ACC_UNIT times operations
	unsigned int searchMAtot;
	unsigned int insertMAtot;
	unsigned int removeMAtot;

	//Count
	unsigned int NumKicked; //number of items kicked successfully
	unsigned int NumBlindKickSucc; //number of item blindly kicked successfully
	unsigned int NumBlindKickFail; //number of item blindly kicked failed
};

