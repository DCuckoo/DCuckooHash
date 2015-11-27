#ifndef cuckooHASH
#define cuckooHASH

#include "key-value.h"
#include "hash_function.h"
#include "define.h"
#include "std_bf.h"

#define KEYLENGTH 19 //include char \0
#define MAX_KICK_TIMES 500 //max times of kicking
class cuckooHash
{
public:
	cuckooHash(void);
	~cuckooHash(void);
	/*
	lenHashTab: Total length of two hash tables
	indexHashFunc1: index of Hash Func1
	indexHashFunc2: index of Hash Func2
	*/
	cuckooHash(unsigned int lenHashTab, unsigned int indexHashFunc1 = 0, unsigned int indexHashFunc2= 1);
	/*
	initial hash table using entries from InputFile
	*/
	/*
	ht_times: the ratio of length of two hash tables and the number of elements to insert
	indexHashFunc1: index of Hash Func1
	indexHashFunc2: index of Hash Func2
	*/
	cuckooHash(unsigned int NumElements, float ht_times, unsigned int indexHashFunc1 = 0, unsigned int indexHashFunc2= 1);
	bool initialFromFile(char *InputFileName, float ht_times,  unsigned int indexHashFunc1 = 0, unsigned int indexHashFunc2= 1);
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
	inline void swap(hashentry* entryA, hashentry* entryB);
public:
	uint (* cockooHashFunc[2])(const unsigned char * str, uint len);

	unsigned int totsize; //total size of hash table
	unsigned int lenPerTab;
	unsigned lenSLChain; //len of singly linked chain
	hashentry ** HashTab;
	hashentryP *singlyLinkedChain;
	unsigned int NumCollisions;
	float *loadingfactor; //loading factor of each table
	float loadingfactorT; //loading factor of total hash tables

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

#endif