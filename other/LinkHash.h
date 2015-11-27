#ifndef LHASH
#define LHASH

#include "key-value.h"
#include "hash_function.h"
#include <iostream>
#include <stdio.h>
#include <fstream>


#define HASH_ENTRY_MAX 500000
#define HASH_SIZE	1021
#define HT_SIZE_TIMES 10
using namespace std;

class LHash
{
public:
	int tblen;
	int numCollisions;
	hashentryP * hashtable;
	int iFunc1;
	double loadingfactor;

public:
	LHash();
	LHash(int tablesize);
	bool initialFromFile(char *inputfile, float ht_times);
	bool test(char*inputfile); 	
	bool insert(const unsigned char *key, int value);
	bool remove(const unsigned char *key);
	bool search(const unsigned char *key,int & value);
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

LHash::LHash()
{
	tblen=0;
	numCollisions=0;
	iFunc1=1;
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

LHash::LHash(int tablesize)
{
	tblen=0;
	numCollisions=0;
	iFunc1=1;
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


	tblen=tablesize;
	hashtable=new hashentryP[tblen];

	for (int k=0; k<tblen; k++)
	{
		memset(hashtable[k].key,0,KEY_SIZE);
		hashtable[k].value=0;
		hashtable[k].next=NULL;
	}
}


bool LHash::reset()
{
	tblen=0;
	numCollisions=0;
	iFunc1=1;
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

bool LHash::initialFromFile(char *inputfile, float ht_times)
{
	numCollisions=0;
	int lines=0;
	hashentryP * pHashentries=readHashEntriesPointer(lines, inputfile);

	tblen = ht_times*lines;
	hashtable=new hashentryP[tblen];
	
	for (int k=0; k<tblen; k++)
	{
		memset(hashtable[k].key,0,KEY_SIZE);
		hashtable[k].value=0;
		hashtable[k].next=NULL;
	}

	for (int i=0; i<lines; i++)
	{
		insert(pHashentries[i].key, pHashentries[i].value);
	}

	if(pHashentries)delete []pHashentries;
	return true;
}



bool LHash::test(char *inputfile)
{
	int lines=0;
	//hashentryP * pHashentries=new hashentryP[500000];
	//memset(pHashentries,0,sizeof(hashentryP)*500000);
	hashentryP * pHashentries=readHashEntriesPointer(lines, inputfile);

	hashentryP * point=new hashentryP;	
	//hashentryP * pHashtable=new hashentryP[tablelen];
	/*for (int k=0; k<tablelen; k++)
	{
		memset(pHashtable[k].key,0,KEY_SIZE);
		pHashtable[k].value=0;
		pHashtable[k].next=NULL;
	}*/
	
	for (int i=0; i<lines; i++)
	{
		pHashentries[i].next=NULL;
		int len=strlen((const char *)(pHashentries[i].key));
		unsigned int a=hash_func[iFunc1]((const unsigned char *)(pHashentries[i].key), len);
		unsigned int pos=a % tblen;
		point = & hashtable[pos];

		while (point!=NULL)
		{
			if (!memcmp((void *)pHashentries[i].key, (void *)point->key, len) && pHashentries[i].value==point->value)break;
			point=point->next;
		}
		if(NULL==point)
		{
			cout<<"test failure"<<endl;
			return false;
		}
		
		//while((strcmp((const char *)pHashentries[i].key, (const char *)point->key) != 0&& point->next!=NULL)||(strcmp((const char *)point->key, (const char *)pHashentries[i].key) == 0 && point->value !=pHashentries[i].value ))
		//{
		//	/*static int i=1;
		//	printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		//	//numCollisions++;
		//	point=point->next;
		//}
		//if(strcmp((const char *)pHashentries[i].key, (const char *)point->key) == 0 && point->value==pHashentries[i].value)
		//{
		//	int kkk=0;
		//}
		//else 
		//{
		//	cout<<"test failure"<<endl;
		//	return 0;
		//}
	}

	/*printf("factor/collisions/ratio:\t%d:\t%d\t%.7f\n",factor, numCollisions, (0.0+numCollisions)/lines); 
	fprintf(f_out, "%.7f\t", (0.0+numCollisions)/lines);*/
	delete [] pHashentries;
	return 1;
}

bool LHash::insert(const unsigned char *key, int value)
{
	//insert count from 1 to MEMORY_ACC_UNIT 
	if (insertCount < MEMORY_ACC_UNIT)
	{
		insertCount++;
	}
	else
	{
		insertCount = 1;
		insertMemAcc[insertMAcurpos] = 1.0*insertMAtot/MEMORY_ACC_UNIT;
		insertMAcurpos++;
		insertMAtot = 0;
	}

	hashentryP * entry= new hashentryP();
	//*entry->key= *key;
	memcpy(entry->key, key, strlen((const char *)key));
	entry->value = value;
	entry->next = NULL;

	int len=strlen((const char *)key);
	unsigned int a=hash_func[iFunc1]((const unsigned char *)key, len);
	unsigned int pos=a % (tblen);
	insertMAtot++;

	
	if( hashtable[pos].value != 0)
	{
		/*static int i=1;
		printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		numCollisions++;
		insertMAtot++;
		entry->next= hashtable[pos].next;
		hashtable[pos].next= entry;
		
	}
	else
	{
		memcpy(hashtable[pos].key, key, len);
		hashtable[pos].value=value;
	}
	return true;
}

bool LHash::remove(const unsigned char *key)
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
	unsigned int pos=a % (tblen);
	hashentryP * point = & hashtable[pos];
	hashentryP * ptt = & hashtable[pos];
	removeMAtot++; 
	while(strcmp((const char *)point->key, (const char *)key) != 0 && point->next != NULL)
	{
		/*static int i=1;
		printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
		ptt = point;
		point = point->next;
		removeMAtot++; 

	}

	if( strcmp((const char *)point->key,(const char *)key) == 0)
	{
		removeMAtot++; 
		ptt->next = point->next;
		return 1;
	}
	else
	{
		printf("delete fail");
		return 0;
	}
}

bool LHash::search(const unsigned char * key, int & value)
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
	unsigned int pos=hash_func[iFunc1]((const unsigned char *)key, len) % tblen;
	hashentryP * point = & hashtable[pos];
	searchMAtot++;

	while(point->next != NULL)
	{
		searchMAtot++;
		if(!memcpy(point->key, key, len))
		{
			value=point->value;
			break;
		}

		point = point->next;
	}

	if (NULL==point)
	{
		printf("search failed\n");
	}

	return true;

	//while(memcpy(point->key, key) != 0 && point->next != NULL)
	//{
	//	/*static int i=1;
	//	printf("pos=%d\t, here key_value=%s<->%u, there are %d hash collison...\n",pos, pHashentries[i].key, pHashtable[pos].value, i++);*/
	//	searchMAtot++;
	//	point = point->next;
	//}

	//if( strcmp((const char *)point->key,(const char *)key) == 0)
	//{
	//	value=point->value;
	//	//cout<<"search success"<<endl;
	//	return 1;
	//}
	//else
	//{
	//	printf("lookup fail");
	//	return 0;
	//}
}
void LHash::collect(void)
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

void LHash::report(char *outputfile)
{

	FILE *file = fopen(outputfile, "w");
	collect();
	fprintf((FILE *)file,"LinkHash\n");
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
bool LHash::Drop_Hash_Table()
{
	delete [] hashtable;
	return 1;
}

#endif