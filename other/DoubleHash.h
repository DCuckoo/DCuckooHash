#ifndef DHASH
#define DHASH

#include "key-value.h"
#include "hash_function.h"
#include <iostream>
#include <stdio.h>
#include <fstream>
#include "define.h"

#define HASH_ENTRY_MAX 500000
#define HASH_SIZE	1021
#define HT_SIZE_TIMES 10
using namespace std;

class DHash
{
public:
	int tblen;
	int numCollisions;
	hashentry * hashtable;
	int failure_NUM;
	int iFunc1;
	int iFunc2;
	double loadingfactor;
public:
	DHash();
	bool initialFromFile(char *inputfile, float ht_times);
	bool test(char*inputfile); 
	bool insert(const unsigned char *key, int value);
	bool remove(const unsigned char *key);
	bool search(const unsigned char *key, int & value);
	bool Drop_Hash_Table();
	bool reset();
	void collect(void);
	void report(char *outputfile);
public:
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

DHash::DHash()
{
	tblen=0;
	numCollisions=0;
	failure_NUM=0;
	iFunc1=1;
	iFunc2=2;
	loadingfactor=0;
	//Count for search insert and remove operation
	searchCount = 0;
	insertCount = 0;
	removeCount = 0;

	//XXXMemAcc is a array contains the average memory access times over 100 operations of XXX
	 memset(searchMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 memset(removeMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 memset(insertMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 

	//XXXMAcurpos is a integer represents the index of the leftmost unused slot in XXXMemAcc
	searchMAcurpos = 0;
	insertMAcurpos = 0;
	removeMAcurpos = 0;

	//XXXMAtot is a temporal variable represents the sum of  Memory access times before, which will be reset after MEMORY_ACC_UNIT times operations
	searchMAtot = 0;
	insertMAtot = 0;
	removeMAtot = 0;

}

bool DHash::reset()
{
	tblen=0;
	numCollisions=0;
	failure_NUM=0;
	iFunc1=1;
	iFunc2=2;
	loadingfactor=0;
	//Count for search insert and remove operation
	searchCount = 0;
	insertCount = 0;
	removeCount = 0;

	//XXXMemAcc is a array contains the average memory access times over 100 operations of XXX
	 memset(searchMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 memset(removeMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 memset(insertMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(unsigned int));
	 

	//XXXMAcurpos is a integer represents the index of the leftmost unused slot in XXXMemAcc
	searchMAcurpos = 0;
	insertMAcurpos = 0;
	removeMAcurpos = 0;

	//XXXMAtot is a temporal variable represents the sum of  Memory access times before, which will be reset after MEMORY_ACC_UNIT times operations
	searchMAtot = 0;
	insertMAtot = 0;
	removeMAtot = 0;
	return 1;
}
//factor:  (sizeof)table/#elements
bool DHash::initialFromFile(char *inputfile, float ht_times)
{
	numCollisions=0;
	int lines=0;
	//hashentry * pHashentries=new hashentry[500000];
	//memset(pHashentries,0,sizeof(hashentry)*500000);
	hashentry * pHashentries=readHashEntries(lines, inputfile);

	tblen = ht_times*lines;
	hashtable=new hashentry[tblen];
	
	for (int k=0; k<tblen; k++)
	{
		memset(hashtable[k].key,0,KEY_SIZE);
		hashtable[k].value=0;
	}
	
	for (int i=0; i<lines; i++)
	{
		insert(pHashentries[i].key,pHashentries[i].value);
		//int len=strlen((const char *)(pHashentries[i].key));
		//unsigned int a=hash_func[iFunc1]((const unsigned char *)(pHashentries[i].key), len);
		//unsigned int b=hash_func[iFunc2]((const unsigned char *)(pHashentries[i].key), len);
		//unsigned int pos=a % (tblen);

		//int n=0;
		//while( n<KICK_COUNT_MAX && hashtable[pos].value != 0 && strcmp((const char *)pHashtable[pos].key, (const char *)pHashentries[i].key) != 0)
		//{
		//	n++;
		//	pos=(a+n*b) % (tblen);
		//	/*static int i=1;
		//	printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		//	numCollisions++;
		//}
		//
		//if (n==KICK_COUNT_MAX)
		//{
		//	failure_NUM++;
		//	cout<<"kick failure  "<<failure_NUM<<endl;
		//}
		//else 
		//{ 
		//	memcpy(pHashtable[pos].key, pHashentries[i].key, len);
		//	pHashtable[pos].value=pHashentries[i].value;
		//}
	}

	/*printf("factor/collisions/ratio:\t%d:\t%d\t%.7f\n",factor, numCollisions, (0.0+numCollisions)/lines); 
	fprintf(f_out, "%.7f\t", (0.0+numCollisions)/lines);*/
	delete [] pHashentries;
	return 1;
}

bool DHash::test(char *inputfile)
{
	int lines=0;
	//hashentry * pHashentries=new hashentry[500000];
	//memset(pHashentries,0,sizeof(hashentry)*500000);
	hashentry *pHashentries=readHashEntries(lines, inputfile);
	
	/*hashentry * pHashtable=new hashentry[tablelen];
	
	for (int k=0; k<tablelen; k++)
	{
		memset(pHashtable[k].key,0,KEY_SIZE);
		pHashtable[k].value=0;
	}*/
	
	for (int i=0; i<lines; i++)
	{
		int len=strlen((const char *)(pHashentries[i].key));
		unsigned int a=hash_func[iFunc1]((const unsigned char *)(pHashentries[i].key), len);
		unsigned int b=hash_func[iFunc2]((const unsigned char *)(pHashentries[i].key), len);
		unsigned int pos=a % (tblen);

		int n=0;
		while( n<KICK_COUNT_MAX && strcmp((const char *)hashtable[pos].key, (const char *)pHashentries[i].key) != 0 ||(strcmp((const char *)hashtable[pos].key, (const char *)pHashentries[i].key) == 0 && hashtable[pos].value !=pHashentries[i].value ))
		{
			n++;
			pos=(a+n*b) % (tblen);
			/*static int i=1;
			printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
			//numCollisions++;
		}
		
		if((strcmp((const char *)hashtable[pos].key, (const char *)pHashentries[i].key) == 0&&hashtable[pos].value==pHashentries[i].value)||n==KICK_COUNT_MAX){}
		else 
		{cout<<"test failure"<<endl;return 0;}
	}

	/*printf("factor/collisions/ratio:\t%d:\t%d\t%.7f\n",factor, numCollisions, (0.0+numCollisions)/lines); 
	fprintf(f_out, "%.7f\t", (0.0+numCollisions)/lines);*/
	delete [] pHashentries;
	return 1;
}

bool DHash::insert(const unsigned char *key, int value)
{
	//insert count from 1 to MEMORY_ACC_UNIT 
	if (insertCount < MEMORY_ACC_UNIT)
	{
		insertCount++;
	}
	else
	{
		insertCount = 1;
		insertMemAcc[insertMAcurpos] = (0.0+insertMAtot)/MEMORY_ACC_UNIT;
		insertMAcurpos++;
		insertMAtot = 0;
	}
	int len=strlen((const char *)key);
	unsigned int a=hash_func[iFunc1]((const unsigned char *)key, len);
	unsigned int b=hash_func[iFunc2]((const unsigned char *)key, len);
	unsigned int pos=a % (tblen);

	int n=0;
	insertMAtot++;
	while(* hashtable[pos].key != 0 && strcmp((const char *)hashtable[pos].key,(const char *)key) != 0 && n<KICK_COUNT_MAX)
	{
		insertMAtot++;
		n++;
		pos=(a+n*b) % (tblen);
		/*static int i=1;
		printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		numCollisions++;
	}

	if (n==KICK_COUNT_MAX)
	{
		failure_NUM++;
		printf("insertion failure, counter=%d\n", failure_NUM);
		return 0;
	}
	else 
	{ 
		memcpy(hashtable[pos].key, (const char *)key, len);
		hashtable[pos].value=value;
		return 1;
	}
}

bool DHash::remove(const unsigned char *key)
{	
	//remove count from 1 to MEMORY_ACC_UNIT 
	if (removeCount < MEMORY_ACC_UNIT)
	{
		removeCount++;
	}
	else
	{
		removeCount = 1;
		removeMemAcc[removeMAcurpos] = 1.0*removeMAtot/MEMORY_ACC_UNIT;
		removeMAcurpos++;
		removeMAtot = 0;
	}

	int len=strlen((const char *)key);
	unsigned int a=hash_func[iFunc1]((const unsigned char *)key, len);
	unsigned int b=hash_func[iFunc2]((const unsigned char *)key, len);
	unsigned int pos=a % (tblen);

	int n=0;
	removeMAtot++; 
	while(n <KICK_COUNT_MAX && strcmp((const char *)hashtable[pos].key,(const char *)key) != 0 )
	{
		n++;
		pos=(a+n*b) % (tblen);
			removeMAtot++; 

		/*static int i=1;
		printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
	}

	if( strcmp((const char *)hashtable[pos].key,(const char *)key) == 0)
	{
		memset(hashtable[pos].key,0,len);
		hashtable[pos].value=0;
		return 1;
	}
	else
	{
		printf("delete fail");
		return 0;
	}
	
}

bool DHash::search(const unsigned char * key,int & value)
{
		//search count from 1 to MEMORY_ACC_UNIT 
	if (searchCount < MEMORY_ACC_UNIT)
	{
		searchCount++;
	}
	else
	{
		searchCount = 1;
		searchMemAcc[searchMAcurpos] = (0.0+searchMAtot)/MEMORY_ACC_UNIT;
		searchMAcurpos++;
		searchMAtot = 0;
	}
	int len=strlen((const char *)key);
	unsigned int a=hash_func[iFunc1]((const unsigned char *)key, len);
	unsigned int b=hash_func[iFunc2]((const unsigned char *)key, len);
	unsigned int pos=a % (tblen);

	int n=0;
	searchMAtot++;
	while( memcmp((const char *)hashtable[pos].key, (const char *)key,len) != 0 && n<KICK_COUNT_MAX )
	{
		n++;
		pos=(a+n*b) % (tblen);
		/*static int i=1;
		printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		searchMAtot++;
	}

	if( memcmp((const char *)hashtable[pos].key,(const char *)key,len) == 0)
	{
		value=hashtable[pos].value;
		return true;
	}
	else
	{
		printf("look up fail");
		return false;
	}
}
void DHash::collect(void)
{
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	int tot=0;
	for(int i = 0; i<tblen; i++)
	{
		if(hashtable[i].value != 0) //if the value of the node is 0, then this node is not occupied
			tot++;
	}
	loadingfactor  = 1.0*tot/tblen;
}

void DHash::report(char *outputfile)
{

	FILE *file = fopen(outputfile, "w");
	collect();
	fprintf((FILE *)file,"doubleHash\n");
	fprintf((FILE *)file,"LoadingFactor/NumCollisions: \t%f\t%d\n", loadingfactor, numCollisions); // yt: we need collision rate.

	fprintf(file, "Average Memory Access times in insert\n");
	for(int i = 0; i < insertMAcurpos; i++)
		fprintf(file, "%d\t%.9f\n", i, insertMemAcc[i]);

	fprintf(file, "\nAverage Memory Access times in search\n");
	for(int i = 0; i < searchMAcurpos; i++)
		fprintf(file, "%d\t%.9f\n", i, searchMemAcc[i]);

	fprintf(file, "\nAverage Memory Access times in remove\n");
	for(int i = 0; i < removeMAcurpos; i++)
		fprintf(file, "%d\t%.9f\n", i, removeMemAcc[i]);
	fclose(file);
}

bool DHash::Drop_Hash_Table()
{
	delete [] hashtable;
	return 1;
}

#endif