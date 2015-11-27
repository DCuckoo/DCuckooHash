#pragma once

#include "key-value.h"
#include "std_bf.h"
#include <stdio.h>


#define KEYLENGTH 19 //include char \0
#define MEMACCESS 100 // number of memory access to count



class dleftHash
{
public:
	dleftHash(void);
	/* dleftHash constructor
	Ngroups_p: number of groups in d-left hash;
	SizeperGroup_p: size of a group 
	*/
	dleftHash(unsigned int Ngroups_p, unsigned int SizeperGroup_p);
	dleftHash(int elementNum, float ht_times, unsigned int Ngroups_p); 
	/*
	initial hash table using entries from InputFile
	*/
	bool initialFromFile(char *InputFileName, float ht_times, unsigned int Ngroups_p = 8);
	/*
	key: a key to insert
	val: the corresponding value of key
	if insert successfully, this function will return true, 
	else it will return false;
	*/
	bool insert(char * key , int val);
	bool search(const unsigned char *key, int & val);  //search for a key, but return its value in the hash table
	bool remove(char *key); //remove a key from hash table
	void collect(void); //collect informations about loading factor
	/* report 
	loading factor , number of collisions and the ratio of the number
	of collisions to the total size of hash tables */
	void report(char *file); 
	bool reset();
	bool test(char *File);

	~dleftHash(void);

private:
	unsigned int Ngroups;
	unsigned int SizeperGroup;

	unsigned int totsize; //total size of hash table
	unsigned int *hashlen; // an array contains the size of every hash table

	hashentryP **HashTab; //hash tables

	unsigned int NumCollisions; //Number of Collisions
	float *loadingfactor; //loading factor of each table
	float loadingfactorT; //loading factor of total hash tables

	unsigned int ** NumSigLikedChain; //length of singly linked chain in hash tables

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
//void GenerateAccessdl(dleftHash* dlefthash, int N, char *statfile); //Unit: 1000