#include "PeacockHash.h"


PeacockHash::PeacockHash(void)
{
	//default constructor
	//PeacockHash(100 , 5 , 3); //default initial
}

PeacockHash::PeacockHash( unsigned int len_main, unsigned int r , unsigned int stage)
{
	if(stage <= 1)
	{
		throw("length of stage must larger than 1");
	}
	if(r <= 1)
	{
		throw(" ratio factor must larger than 1");
	}
	if(len_main % (int)pow(r,stage-1) != 0)
	{
		throw(" len_main must be equal to a positive integer times r^(stage-1) ");
	}

	// calculate length of hash tables
	hashlen = new unsigned int[stage];
	hashlen[0] = len_main;
	totsize = len_main;
	unsigned int tmp = len_main;
	for(int i = 1; i < stage; i++)
	{
		tmp = tmp/r;
		hashlen[i] = tmp;
	}

	//initial main hash table
	MainHashTab = new hashentry[len_main];
	memset(MainHashTab , 0 , len_main*sizeof(hashentry));

	//initial sub hash tables
	SubHashTab = new hashentryP* [stage-1];
	for(int i = 1; i < stage ; i++)
	{
		SubHashTab[i-1] = new hashentryP [hashlen[i]];
		memset(SubHashTab[i-1], 0, hashlen[i]*sizeof(hashentryP));
	}
	
	//initial Bloom Filter
	BloomFilter = new StandardBF[stage - 1];
	for(int i = 1; i < stage ; i++)
	{
		BloomFilter[i-1].initial(hashlen[i]*16/0.7 , 6 ); //the second parameter is the number of hash function 
		//used in bloom filter
	}
	
	NumCollisions = 0 ; //initial number of collisions is 
	loadingfactor =  new float[stage]() ;
	loadingfactorT = 0;
	
	ratiofactor = r;
	NumStages = stage;

	// initial array of number of singly linked chain
	NumSigLikedChain = new unsigned int*[stage -1];
	for( int i = 1; i < stage  ;i++)
	{
		NumSigLikedChain[i-1] = new unsigned int[hashlen[i]]();
	}
	//reset memory access account
	reset();
	
}

PeacockHash::PeacockHash( unsigned int elementNum, float ht_times, unsigned int Nstages_p)
{
	unsigned int ratio = 10; //default ratio is 10
	unsigned int totsize =(unsigned int) elementNum*ht_times;
	unsigned int len_main =(unsigned int) 1.0*totsize*(ratio-1)/(ratio-pow(ratio, 1-Nstages_p));
	PeacockHash(len_main, ratio , Nstages_p);
}
PeacockHash::~PeacockHash(void)
{
	// initial array of number of singly linked chain
	
	for( int i = 1; i < NumStages  ;i++)
	{
		delete [] NumSigLikedChain[i-1];
	}
	delete [] NumSigLikedChain;

	delete [] loadingfactor;

	delete [] BloomFilter;


	

	
	for(int i = 1; i < NumStages ; i++)
	{
		hashentryP * hashtabptr = SubHashTab[i-1];
		for(int j = 0; j < hashlen[i]; j++)
		{

			hashentryP* entryptr1 = hashtabptr[j].next;
			while(entryptr1 != NULL)
			{
				hashentryP *entryptr2 = entryptr1->next;
				delete entryptr1;
				entryptr1 = entryptr2;
			}
		}
		delete [] SubHashTab[i-1];
		
	}

	delete [] SubHashTab;


	delete [] hashlen;

	delete [] MainHashTab;



}

bool PeacockHash::initialFromFile(char *InputFileName, float ht_times , unsigned int stage)
{
	//initial Hash Table
	int lines=0;
	//get number of lines of inputfile
	hashentryP * pHashentries=readHashEntriesPointer(lines, InputFileName);
	unsigned int r = 5; //default ratio is 10
	unsigned int totsize = (unsigned int) lines*ht_times;
	
	unsigned int len_last = (unsigned int) 1.0*totsize*(r-1)/(pow(r,stage)-1.0);
	unsigned int len_main = len_last*(unsigned int)pow(r,stage-1);
	
	if(stage <= 1)
	{
		throw("length of stage must larger than 1");
	}
	if(r <= 1)
	{
		throw(" ratio factor must larger than 1");
	}
	if (len_main <= 0)
	{
		throw("len of main hash table must be larger than zero");
	}

	if(len_main % (int)pow(r,stage-1) != 0)
	{
		throw(" len_main must be equal to a positive integer times r^(stage-1) ");
	}

	// calculate length of hash tables
	hashlen = new unsigned int[stage];
	hashlen[0] = len_main;
	totsize = len_main;
	unsigned int tmp = len_main;
	for(int i = 1; i < stage; i++)
	{
		tmp = tmp/r;
		hashlen[i] = tmp;
	}

	//initial main hash table
	MainHashTab = new hashentry[len_main];
	memset(MainHashTab , 0 , len_main*sizeof(hashentry));

	//initial sub hash tables
	SubHashTab = new hashentryP* [stage-1];
	for(int i = 1; i < stage ; i++)
	{
		SubHashTab[i-1] = new hashentryP [hashlen[i]];
		memset(SubHashTab[i-1], 0, hashlen[i]*sizeof(hashentryP));
	}

	//initial Bloom Filter
	BloomFilter = new StandardBF[stage - 1];
	for(int i = 1; i < stage ; i++)
	{
		BloomFilter[i-1].initial(hashlen[i]*16/0.7 , 16 ); //the second parameter is the number of hash function 
		//used in bloom filter
	}

	NumCollisions = 0 ; //initial number of collisions is 
	loadingfactor =  new float[stage]() ;
	loadingfactorT = 0;

	ratiofactor = r;
	NumStages = stage;

	// initial array of number of singly linked chain
	NumSigLikedChain = new unsigned int*[stage -1];
	for( int i = 1; i < stage  ;i++)
	{
		NumSigLikedChain[i-1] = new unsigned int[hashlen[i]]();
	}
	//reset memory access account
	reset();
	//initial completely
	for (int i=0; i<lines; i++)
	{
		insert((char *)pHashentries[i].key, pHashentries[i].value);
	}

	if(pHashentries)delete []pHashentries;
	return true;
}

bool PeacockHash::insert(char * key , int val)
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

	//try to insert key into the main table
	int len=strlen((const char *)(key));
	uint pos=hash_func[0]((const unsigned char *)(key) , len ) % (hashlen[0]);
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	insertMAtot++;
	if (MainHashTab[pos].value == 0) // no collision 
	{
		
		memcpy(MainHashTab[pos].key , key , len);
		MainHashTab[pos].value =val;
		return true;
	}
	/*
	NumCollisions++;    ///yt: why ++ ???????
	reason: different explanation for collision
	*/
	//find a position in sub hash tables
	for( int  i = 1 ; i < NumStages ; i++)
	{
		pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
		
		hashentryP * subhash = SubHashTab[i-1];
		insertMAtot++;
		if (subhash[pos].value == 0 )
		{
			
			
			memcpy(subhash[pos].key,key,len);
			subhash[pos].value = val;
			subhash[pos].next = NULL;

			//update numstage
			/*
			unsigned int *numstage = NumSigLikedChain[i-1];
			numstage[pos]++;
			*/
			//update bloom filter
			BloomFilter[i-1].insert((const unsigned char *)key, len);

			
			return true;
		}
		
	}
	//can not find a empty slot to store the key 
	NumCollisions++;
	//find the minimum length of singly linked chain
	
	int chainlen = 0;
	int index =1;

	for(int i = 1 ; i < NumStages ; i++)
	{
		unsigned int *numstage = NumSigLikedChain[i-1];
		pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
		if ( i == 1)
		{
			
			chainlen = numstage[pos];
			index = 1;
			continue;
		}
		if(numstage[pos] < chainlen)
		{
			chainlen = numstage[pos];
			index = i;
		}
	}	
		//insert key after a singly linked chain with minimum length
	hashentryP * subhash = SubHashTab[index-1];
	pos=hash_func[index % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[index]);
	//insert in the head of singly linked chain
	hashentryP *TempPtr = new hashentryP;
	TempPtr->next = subhash[pos].next;
	subhash[pos].next = TempPtr;
	insertMAtot++;
	
	TempPtr -> value  = val;
	memcpy( TempPtr->key , key , len);
	//update numstage
	unsigned int *numstage = NumSigLikedChain[index-1];
	numstage[pos]++;

	//update bloom filter
	BloomFilter[index-1].insert((const unsigned char *)key, len);
	return true;

}




bool PeacockHash::search(const unsigned char *key , int & value) // yt: record # memory accesses, # hash probes
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

	bool *mask;
	mask = new bool[NumStages];
	mask[0] =false; //mask[0] represents if this key is located in subfilters.

	int len=strlen((const char *)(key)); 
	for( int i = 1; i < NumStages ; i++)
	{
		if(BloomFilter[i-1].query((const unsigned char *) key , len) == 1) //find key in Bloom filter
		{
			mask[0] = true;
			mask[i] = true;
		}
		else
		{
			mask[i] = false;
		}
	}
	uint pos;
	if(mask[0] == true)
	{
		for ( int i = 1; i < NumStages ; i++)
		{
			if(mask[i] == true)
			{
				pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
				hashentryP * subhash = SubHashTab[i-1];
				searchMAtot ++;
				if(memcmp(subhash[pos].key , key , len) == 0)
				{
					delete [] mask;
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
						delete [] mask;
						value = hashptr -> value;
						return true;
					}
				}

			}

		}
	}
	//not find the key in subhash table
	//so we will search it in the main table
		pos=hash_func[0]((const unsigned char *)(key) , len ) % (hashlen[0]); //find the position in main hash table
		searchMAtot++;
		if(memcmp(MainHashTab[pos].key , key , len) == 0)
		{
			delete [] mask;
			value = MainHashTab[pos].value;
			return true;
		}
	
	return false;

}

bool PeacockHash::remove(char *key) //remove a key from hash table
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

	bool *mask;
	mask = new bool[NumStages];
	mask[0] =false; //mask[0] represents if this key is located in subfilters.

	int len=strlen((const char *)(key)); 
	for( int i = 1; i < NumStages ; i++)
	{
		if(BloomFilter[i-1].query((const unsigned char *) key , len) == 1) //find key in Bloom filter
		{
			mask[0] = true;
			mask[i] = true;
		}
		else
		{
			mask[i] = false;
		}
	}
	uint pos;
	if(mask[0] == true)
	{
		for ( int i = 1; i < NumStages ; i++)
		{
			if(mask[i] == true)
			{
				pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i-1]);
				hashentryP * subhash = SubHashTab[i-1];
				removeMAtot++;
				if(memcmp(subhash[pos].key , key , len) == 0)
				{
					if(subhash[pos].next == NULL) 
					{
						subhash[pos].value = 0;
						delete [] mask;
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
						delete [] mask;
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
						delete [] mask;
						//BloomFilter[i-1]; // how to reset BloomFilter
						return true;
					
					}
				
				}

			}
		}
	}
	//not find key in subhashtab
		pos=hash_func[0]((const unsigned char *)(key) , len ) % (hashlen[0]);
		removeMAtot++;
		if(memcmp(MainHashTab[pos].key , key , len) == 0)
		{
			delete [] mask;
			//memset(MainHashTab[pos].key , 0, KEYLENGTH);
			MainHashTab[pos].value = 0;
			return true;
		}
	
	
	return false; // not find this node
}

void PeacockHash::collect(void)
{
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	int *tot;
	tot = new int[NumStages];
	memset(tot , 0 , NumStages*sizeof(int));
	for(int i = 0; i< hashlen[0] ; i++)
	{
		if(MainHashTab[i].value != 0) //if the value of the node is 0, then this node is not occupied
			tot[0]++;
	}
	
	for(int i = 1; i < NumStages; i++)
	{
		hashentryP* hashtab = SubHashTab[i-1];
		for(int j = 0; j < hashlen[i] ; j++)
		{
			if( hashtab[j].value != 0) tot[i]++;
		}
	}
	int totT = 0;
	int tottab = 0;
	for( int i = 0; i < NumStages; i++)
	{
		totT += tot[i];
		tottab += hashlen[i];
		loadingfactor[i] = 1.0*tot[i] / hashlen[i];
	}
	loadingfactorT  = 1.0*totT/tottab;
	delete [] tot;

}

void PeacockHash::report(char *outputfile)
{

	FILE *file = fopen(outputfile, "w");
	collect();
	fprintf((FILE *)file,"PeacockHash\n");
	fprintf((FILE *)file,"LoadingFactor/NumCollisions: %f\t%d\n", loadingfactorT, NumCollisions); // yt: we need collision rate.
	for(int i = 0 ; i < NumStages ; i++)
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


bool PeacockHash::reset()
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


bool PeacockHash::test(char *File)
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
		bool ret = search((const unsigned char *) key, retvalue);
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
