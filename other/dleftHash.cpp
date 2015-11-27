#include "dleftHash.h"


dleftHash::dleftHash(void)
{
	//dleftHash(10,10000);
}

dleftHash::dleftHash(int elementNum, float ht_times, unsigned int Ngroup_p)
{
	dleftHash(Ngroup_p, elementNum*ht_times/Ngroup_p);
}

dleftHash::dleftHash(unsigned int Ngroups_p, unsigned int SizeperGroup_p)
{
	if (Ngroups_p < 1 )
	{
		throw("Number of groups must larger than zero!");
	}
	if(SizeperGroup_p < 1)
	{
		throw("Size of a group must larger than zero!");
	}


	Ngroups = Ngroups_p;
	SizeperGroup = SizeperGroup_p;

	totsize = Ngroups*SizeperGroup;
	
	//initial hashlen
	hashlen = new unsigned int[Ngroups];
	for(int i =0; i< Ngroups ; i++)
	{
		hashlen[i] = SizeperGroup;
	}

	//initial hash table
	HashTab = new hashentryP* [Ngroups];
	for(int i = 0; i < Ngroups ; i++)
	{
		HashTab[i] = new hashentryP [hashlen[i]];
		memset(HashTab[i], 0, hashlen[i]*sizeof(hashentryP));
	}
	NumCollisions = 0 ; //initial number of collisions is 
	loadingfactor =  new float[Ngroups]() ;
	loadingfactorT = 0;

	// initial array of number of singly linked chain
	NumSigLikedChain = new unsigned int*[Ngroups];
	for( int i = 0; i < Ngroups  ;i++)
	{
		NumSigLikedChain[i] = new unsigned int[hashlen[i]]();
	}

	reset();
	//initial completely
}

dleftHash::~dleftHash(void)
{
	for( int i = 0; i < Ngroups  ;i++)
	{
		delete [] NumSigLikedChain[i];
	}
	delete [] NumSigLikedChain;

	delete [] loadingfactor;


	for(int i = 0; i < Ngroups ; i++)
	{
		hashentryP * hashtabptr = HashTab[i];
		for(int j = 0; j < hashlen[i]; j++)
		{
			hashentryP * entryptr1 = hashtabptr[j].next;
			while(entryptr1 != NULL)
			{
				hashentryP *entryptr2 = entryptr1->next;
				delete entryptr1;
				entryptr1 = entryptr2;
			}

		}
		delete [] HashTab[i];
		
	}

	delete [] HashTab;


	delete [] hashlen;

	
}

bool dleftHash::initialFromFile(char *InputFileName, float ht_times , unsigned int Ngroups_p)
{
	//initial Hash Table
	int lines=0;
	//get number of lines of inputfile
	hashentryP * pHashentries=readHashEntriesPointer(lines, InputFileName);
	
	unsigned int SizeperGroup_p  =(unsigned int) lines*ht_times/Ngroups_p;
	if (Ngroups_p < 1 )
	{
		throw("Number of groups must larger than zero!");
	}
	if(SizeperGroup_p < 1)
	{
		throw("Size of a group must larger than zero!");
	}


	Ngroups = Ngroups_p;
	SizeperGroup = SizeperGroup_p;

	totsize = Ngroups*SizeperGroup;

	//initial hashlen
	hashlen = new unsigned int[Ngroups];
	for(int i =0; i< Ngroups ; i++)
	{
		hashlen[i] = SizeperGroup;
	}

	//initial hash table
	HashTab = new hashentryP* [Ngroups];
	for(int i = 0; i < Ngroups ; i++)
	{
		HashTab[i] = new hashentryP [hashlen[i]];
		memset(HashTab[i], 0, hashlen[i]*sizeof(hashentryP));
	}
	NumCollisions = 0 ; //initial number of collisions is 
	loadingfactor =  new float[Ngroups]() ;
	loadingfactorT = 0;

	// initial array of number of singly linked chain
	NumSigLikedChain = new unsigned int*[Ngroups];
	for( int i = 0; i < Ngroups  ;i++)
	{
		NumSigLikedChain[i] = new unsigned int[hashlen[i]]();
	}

	reset();
	//initial completely

	for (int i=0; i<lines; i++)
	{
		insert((char *)pHashentries[i].key, pHashentries[i].value);
	}

	if(pHashentries)delete []pHashentries;

	return true;
}

bool dleftHash::insert(char * key , int val)
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

	//try to insert key intro the main table
	int len=strlen((const char *)(key));
	

	//find a position in sub hash tables
	for( int  i = 0 ; i < Ngroups ; i++)
	{
		uint pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
		
		hashentryP * subhash = HashTab[i];
		insertMAtot++;
		if (subhash[pos].value == 0 )
		{
			
			
			memcpy(subhash[pos].key ,key,len);
			subhash[pos].value = val;
			subhash[pos].next = NULL;

			//update numstage
			unsigned int *numstage = NumSigLikedChain[i];
			numstage[pos]++;
			return true;
		}
		
	}

	//can not find a empty slot to store the key 
	NumCollisions++;
	//find the minimum length of singly linked chain
	
	int chainlen = 0;
	int index =0;

	for(int i = 0 ; i < Ngroups ; i++)
	{
		unsigned int *numstage = NumSigLikedChain[i];
		uint pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
		if ( i == 0)
		{
			
			chainlen = numstage[pos];
			index = 0;
			continue;
		}
		//Here we use <, not <=, because what we implements is d-left hashing
		//Using < , we can select out the leftmost group with minimum chain length
		// Using <= , we will select out the rightmost one, but not the leftmost one.
		// So we use < here.
		if(numstage[pos] < chainlen)
		{
			chainlen = numstage[pos];
			index = i;
		}
	}	
		//insert key after a singly linked chain with minimum length
	hashentryP * subhash = HashTab[index];
	uint pos=hash_func[index % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[index]);
	hashentryP* hashptr = subhash[pos].next;
	//insert in the head of singly linked chain
	hashentryP *TempPtr = new hashentryP;
	TempPtr->next = subhash[pos].next;
	subhash[pos].next = TempPtr;
	insertMAtot++;

	TempPtr -> value  = val;
	memcpy( TempPtr->key , key , len);
	//update numstage
	unsigned int *numstage = NumSigLikedChain[index];
	numstage[pos]++;

	
	return true;

}

bool dleftHash::search(const unsigned char *key , int & value) // yt: record # memory accesses, # hash probes
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

	int len=strlen((const char *)(key)); 
	uint pos;
		
	for ( int i = 0; i < Ngroups ; i++)
	{
		
		pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
		hashentryP * subhash = HashTab[i];
		searchMAtot ++;
		if(memcmp(subhash[pos].key , key , len) == 0)
		{
			value = subhash[pos].value;
			return true;
		}
		//reach the end of chain

		hashentryP* hashptr = subhash[pos].next;
		for ( ; hashptr != NULL ; hashptr = hashptr -> next)
		{
			searchMAtot++;
			if(memcmp(hashptr->key , key , len) == 0)
			{
				value = hashptr -> value;
				return true;
			}
		}
	}
			
	
	//can not find key 
	return false;

}

bool dleftHash::remove(char *key) //remove a key from hash table
{
	
	//remove count from 1 to MEMORY_ACC_UNIT 
	if (removeCount < MEMORY_ACC_UNIT)
	{
		removeCount++;
	}
	else
	{
		removeCount = 1;
		removeMemAcc[removeMAcurpos] = (0.0+removeMAtot)/MEMORY_ACC_UNIT;
		removeMAcurpos++;
		removeMAtot = 0;
	}

	int len=strlen((const char *)(key)); 
	uint pos;
	for ( int i = 0; i < Ngroups ; i++)
	{
		pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i-1]);
		hashentryP * subhash = HashTab[i];
		removeMAtot++;
		if(memcmp(subhash[pos].key , key , len) == 0)
		{
			if(subhash[pos].next == NULL) 
			{
				subhash[pos].value = 0;
				//BloomFilter[i-1]; // how to reset BloomFilter
				return true;
			}
			else
			{
				memcpy(subhash[pos].key,subhash[pos].next->key, KEYLENGTH);
				removeMAtot++; // subhash[pos].next->value;
				subhash[pos].value = subhash[pos].next->value;
				hashentryP* todelete = subhash[pos].next;
				subhash[pos].next = subhash[pos].next->next;
				delete todelete;
				return true;
			}

		}
		//check linked chain
		hashentryP* hashptr1 = subhash[pos].next;
		hashentryP* hashptr2 = subhash[pos].next;
		//reach the end of chain
		for ( ; hashptr2 != NULL ; hashptr2 = hashptr2 -> next)
		{

			/*make hashptr1 == hashptr2 */

			hashptr1 = hashptr2;

			removeMAtot++;
			if(memcmp(hashptr2->key , key , len) == 0)
			{

				hashptr1 = hashptr2->next;

				delete hashptr2; //delete node
				//BloomFilter[i-1]; // how to reset BloomFilter
				return true;

			}

		}
	
	}
	
	return false; // not find this node
}

void dleftHash::collect(void)
{
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	int *tot;
	tot = new int[Ngroups];
	memset(tot , 0 , Ngroups*sizeof(int));
	
	
	for(int i = 0; i < Ngroups; i++)
	{
		hashentryP* hashtab = HashTab[i];
		for(int j = 0; j < hashlen[i] ; j++)
		{
			if( hashtab[j].value != 0) tot[i]++;
		}
	}
	int totT = 0;
	int tottab = 0;
	for( int i = 0; i < Ngroups; i++)
	{
		totT += tot[i];
		tottab += hashlen[i];
		loadingfactor[i] = 1.0*tot[i] / hashlen[i];
	}
	loadingfactorT  = 1.0*totT/tottab;
	delete [] tot;

}

void dleftHash::report(char *Outputfile)
{
	collect();
	FILE* file = fopen(Outputfile,"w");
	fprintf((FILE *)file,"dleftHash\n");
	fprintf((FILE *)file,"LoadingFactor/NumCollisions:\t%f\t%d\n", loadingfactorT, NumCollisions); // yt: we need collision rate.
	for(int i = 0 ; i < Ngroups ; i++)
	{
		printf("LoadingFactor%d: %f\n",i , loadingfactor[i]);
		fprintf((FILE *)file,"LoadingFactor%d: %f\n",i , loadingfactor[i]);
	}


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

bool dleftHash::reset()
{

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

	return true;
}

bool dleftHash::test(char *File)
{
	FILE *f_input = fopen(File, "r");
	if (NULL == f_input)  //If FilePtr is NULL
	{
		fprintf(stderr, "error: File doesn't exist\n");
		return false;
	}
	int nofound = 0;
	char *key;
	key = new char[KEYLENGTH];
	memset(key , 0 , KEYLENGTH);
	int  value;
	while (!feof(f_input))
	{
		fscanf(f_input, "%s %u", key, &value);
		int retvalue;
		bool ret = search((const unsigned char *)key, retvalue);
		if(ret == false || retvalue != value) 
		{
			nofound++;

		}
	}
	fclose(f_input);
	if (nofound != 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}
