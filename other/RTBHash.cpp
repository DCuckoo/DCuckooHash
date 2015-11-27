#include "RTBHash.h"


RTBHash::RTBHash(void)
{
	//default constructor
	//RTBHash(4000,2000,3);
	Collisions_nokick=0;
}


RTBHash::~RTBHash(void)
{
	blind_kick_num=0;
	delete [] NumSigLikedChain;
	delete [] loadingfactor;

	for (int i =0 ; i < NumStages; i++)
	{
		delete [] bitsetGrpPtr[i];
		
	}

	delete [] bitsetGrpPtr;
	delete  lowPartBF;

	delete mulbitBF;

	for(int i =0 ; i < NumStages; i++)
	{
		delete [] HashTab[i];
	}
	delete [] HashTab;

	delete [] hashlen;
	
	
	
}
RTBHash::RTBHash( unsigned int elementNum, float ht_times, unsigned int Nstages_p )
{
	blind_kick_num=0;
	int totlen = elementNum*ht_times;
	unsigned int comdif  = 5000;

	unsigned int LenLastHashTab=comdif/2-comdif*Nstages_p/2+totlen/Nstages_p;
	RTBHash aHashtable(LenLastHashTab , comdif , Nstages_p);

	Collisions_nokick=0;
}
RTBHash::RTBHash(unsigned int LenLastHashTab, unsigned int comdiff, unsigned int stages)
{
	blind_kick_num=0;
	if(stages > 16)
	{

		throw("number of stages must less than or equal to 16");
	}
	if(stages < 2)
	{
		throw("number of stages must larger than or equal 2");
	}
	if (stages%2 != 0)
	{
		throw("number of stages must be even");
	}
	if (LenLastHashTab < 1 || comdiff < 1 )
	{
		throw("Length of last hash tab and common difference must be larger than zero");
	}
	

	//initial numbers of groups and stages
	NumGroups = stages/2;
	NumStages = stages;

	//initial length of hash tables
	totsize = 0; //reset totsize
	hashlen = new unsigned int[stages];
	for (int i = NumStages-1; i >= 0; i--)
	{
		if (i == NumStages-1)
		{
			hashlen[i] = LenLastHashTab;
		}
		else
		{
			hashlen[i] = hashlen[i+1] + comdiff;
		}
		totsize += hashlen[i];

	}
	//initial group length
	grouplen = hashlen[0]+hashlen[stages-1];
	
	//initial hashtable
	HashTab = new hashentryP* [stages];
	//initial sub hash table
	for(int i =0 ; i < NumStages; i++)
	{
		HashTab[i] = new hashentryP[hashlen[i]];
		memset(HashTab[i], 0, hashlen[i]*sizeof(hashentryP));
	}
	//initial multibit bloom filter
	int BFsize=grouplen*NUM_HASH_FUNCTION_IN_BF/0.7;
	mulbitBF = new multibitBF(BFsize, NUM_HASH_FUNCTION_IN_BF); //the second parameter is the number of hash functions used in bloom filter
	int lowPartLen = 0;
	for (int i = NumGroups; i < stages; i++)
	{
		lowPartLen += hashlen[i];
	}
	int lowerBFsize=lowPartLen*16/0.7;
	lowPartBF = new StandardBF(lowerBFsize, NUM_HASH_FUNCTION_IN_BF);
	bitsetGrpPtr = new bool*[stages];
	for (int i =0 ; i < NumStages; i++)
	{
		bool * groupPtr;
		groupPtr = new bool[hashlen[i]];
		bitsetGrpPtr[i] = groupPtr;
		for(int j = 0; j  < hashlen[i]; j++) groupPtr[j] = false;
	}

	NumCollisions = 0;
	loadingfactor = new float[NumStages]; //loading factor of each table
	memset(loadingfactor , 0, NumStages*sizeof(float));
	loadingfactorT = 0; //loading factor of total hash tables
	
	NumLoading = new unsigned int[NumStages];
	memset(NumLoading, 0, NumStages*sizeof(unsigned int));

	NumSigLikedChain = new unsigned int[hashlen[NumStages-1]]; //length of singly linked chain in last hash table 
	memset(NumSigLikedChain, 0 , hashlen[NumStages-1]*sizeof(unsigned int));
	//reset memory access times counter
	reset();
	//initial completely
}

bool RTBHash::initialFromFile(char *InputFileName, float ht_times,unsigned int Nstages_p)
{

	//initial
	//initial Hash Table
	int lines=0;
	//get number of lines of inputfile
	hashentryP * pHashentries=readHashEntriesPointer(lines, InputFileName);

	unsigned int totlen = lines*ht_times;
	unsigned int comdif  = 5000;
	unsigned int LenLastHashTab=comdif/2-comdif*Nstages_p/2+totlen/Nstages_p;

	unsigned int stages = Nstages_p;
	unsigned int comdiff = comdif;

	if(stages > 16)
	{

		throw("number of stages must less than or equal to 16");
	}
	if(stages < 2)
	{
		throw("number of stages must larger than or equal 2");
	}
	if (stages%2 != 0)
	{
		throw("number of stages must be even");
	}
	if (LenLastHashTab < 1 || comdiff < 1 )
	{
		throw("Length of last hash tab and common difference must be larger than zero");
	}


	//initial numbers of groups and stages
	NumGroups = stages/2;
	NumStages = stages;

	//initial length of hash tables
	totsize = 0; //reset totsize
	hashlen = new unsigned int[stages];
	for (int i = NumStages-1; i >= 0; i--)
	{
		if (i == NumStages-1)
		{
			hashlen[i] = LenLastHashTab;
		}
		else
		{
			hashlen[i] = hashlen[i+1] + comdiff;
		}
		totsize += hashlen[i];

	}
	//initial group length
	grouplen = hashlen[0]+hashlen[stages-1];

	//initial hashtable
	HashTab = new hashentryP* [stages];
	//initial sub hash table
	for(int i =0 ; i < NumStages; i++)
	{
		HashTab[i] = new hashentryP[hashlen[i]];
		memset(HashTab[i], 0, hashlen[i]*sizeof(hashentryP));
	}
	//initial multibit bloom filter
	int BFsize=grouplen*NUM_HASH_FUNCTION_IN_BF/0.7;
	mulbitBF = new multibitBF(BFsize, NUM_HASH_FUNCTION_IN_BF); //the second parameter is the number of hash functions used in bloom filter
	int lowPartLen = 0;
	for (int i = NumGroups; i < stages; i++)
	{
		lowPartLen += hashlen[i];
	}
	int lowerBFsize=lowPartLen*16/0.7;
	lowPartBF = new StandardBF(lowerBFsize, NUM_HASH_FUNCTION_IN_BF);
	bitsetGrpPtr = new bool*[stages];
	for (int i =0 ; i < NumStages; i++)
	{
		bool * groupPtr;
		groupPtr = new bool[hashlen[i]];
		bitsetGrpPtr[i] = groupPtr;
		for(int j = 0; j  < hashlen[i]; j++) groupPtr[j] = false;
	}

	NumCollisions = 0;
	loadingfactor = new float[NumStages]; //loading factor of each table
	memset(loadingfactor , 0, NumStages*sizeof(float));
	loadingfactorT = 0; //loading factor of total hash tables

	NumLoading = new unsigned int[NumStages];
	memset(NumLoading, 0, NumStages*sizeof(unsigned int));

	NumSigLikedChain = new unsigned int[hashlen[NumStages-1]]; //length of singly linked chain in last hash table 
	memset(NumSigLikedChain, 0 , hashlen[NumStages-1]*sizeof(unsigned int));
	//reset memory access times counter
	reset();

	//initial completely

	//initial counter
	int inserted = 0;
	while(inserted != lines)
	{
		char *key = (char *)pHashentries[inserted].key;
		int val = pHashentries[inserted].value;
		/*
		if (memcmp(key,"1.0.0.0/24",10) ==0)
		{
			printf("found!");
		}
		*/
#ifdef _DEBUG
		if (memcmp(key,"2.189.64.0/22", 13) == 0)
		{
			printf("found!\n");
		}
#endif
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
		for( int  i = 0 ; i < NumStages ; i++)
		{
			
			uint pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);

			hashentryP * subhash = HashTab[i];
			insertMAtot++;
			bool *groupPtr = bitsetGrpPtr[i];
			if (groupPtr[pos] == false )
			{
				//find hashTables has minimum loading factor
				{
					int indexMinLoading = i;
					int NumLoadingMin = NumLoading[i];
					int LenHashTabMin = hashlen[i]; //length of Hash Tab with minimum Loading
					for (int idex = i+1 ; idex < NumStages ; idex++)
					{
						uint posMoveToA=hash_func[idex % HASH_NUM_MAX]((const unsigned char *)(key)	 , len ) % (hashlen[idex]);
						bool *GroupmaskA = bitsetGrpPtr[idex];
						if (GroupmaskA[posMoveToA] == false)
						{
							if (1.0*NumLoading[idex]/hashlen[idex] < 1.0*NumLoadingMin/LenHashTabMin) //find a bucket in a hash table with less loadings
							{
								NumLoadingMin = NumLoading[idex]; 
								LenHashTabMin = hashlen[idex];
								indexMinLoading = idex;
							}
						}
					}
					//insert into hash table with minimum loading 
					if (indexMinLoading != i)
					{
						 i = indexMinLoading;
						pos=hash_func[indexMinLoading % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[indexMinLoading]);
						subhash = HashTab[indexMinLoading];
						groupPtr = bitsetGrpPtr[indexMinLoading];
						
					}

				}

				memcpy(subhash[pos].key ,key,len);
				subhash[pos].value = val;

				//mask corresponding bit
				
				groupPtr[pos] = true;
				//increase Number of loaded buckets in this hash table by 1
				NumLoading[i]++;
				//next loop
				goto END_INSERT;
			}

		}

		//can not find a empty slot to store the key 
		NumCollisions++;

		//store it in the singly linked chain of last hash table
		uint pos  = hash_func[NumStages-1 % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[NumStages-1]);
		//insert in the head of singly linked chain
		hashentryP * subhash = HashTab[NumStages-1];
		hashentryP *TempPtr =new hashentryP;
		memset(TempPtr, 0, sizeof(hashentryP));
		TempPtr->next = subhash[pos].next;
		subhash[pos].next = TempPtr;
		insertMAtot++;

		TempPtr -> value  = val;
		memcpy( TempPtr->key , key , len+1);
		//update the number of corresponding singly linked chain
		NumSigLikedChain[pos]++;
		
END_INSERT:
		inserted++;
		continue;
	}	
	
	if(pHashentries)delete []pHashentries;
//#ifdef _DEBUG	
	//printf("\nNumCollisions after first stage of insertion, no kick\n");
	//report("AfterFirstStage.txt");
//#endif
	Collisions_nokick=NumCollisions;


	//find pointer to the end node of singly linked chain
	hashentryP ** pEnd;
	pEnd = new hashentryP*[hashlen[NumStages-1]];
	memset(pEnd, 0 , hashlen[NumStages-1]*sizeof(hashentryP *));
	hashentryP* lastTab = HashTab[NumStages-1];
	for (int i = 0; i < hashlen[NumStages-1]; i++)
	{
		if (lastTab[i].next == NULL)
		{
			pEnd[i] = &(lastTab[i]);
		}
		else
		{
			hashentryP * pEntry = lastTab[i].next;
			while (pEntry->next != NULL)
			{
				pEntry = pEntry->next;
			}
			pEnd[i] = pEntry;
		}
	}

	//try to kick key and value pairs in the singly linked chain of last hash table to the preceding hash tables
	for(int i = 0 ; i < hashlen[NumStages-1]; i++)
	{//for each bucket in the last hash table
		if (NumSigLikedChain[i] > 0) // the singly linked chain is not empty
		{
			hashentryP * subhashlast = HashTab[NumStages-1];
			
			insertMAtot++;

			int state = STATE_KICK;
			hashentryP* extraNode;
			int StageToTry = 0;
			while ((subhashlast[i].next != NULL && subhashlast[i].next->IsKICKED == false) || state == STATE_BLIND_KICK)
			{
#ifdef _DEBUG
				if (i == 42401)
				{
					printf("get 42401");
				}
#endif
				hashentryP* node = subhashlast[i].next; //head node of chain
				insertMAtot++;
				if (state == STATE_KICK)
				{
					//first try to kick the node in candinate postions
					int len=strlen((const char *)(node->key));
					bool kicked = false;
					//find a position in sub hash tables
					for( int  j = 0 ; j < NumStages ; j++)
					{
						uint pos=hash_func[j % HASH_NUM_MAX]((const unsigned char *)(node->key) , len ) % (hashlen[j]);

						hashentryP * subhash = HashTab[j];
						insertMAtot++;
						char *keytokick = (char *) subhash[pos].key;
						int lentokick=strlen((const char *)(keytokick));
						for (int nextpos = 0; nextpos < NumStages ;nextpos++)
						{
							if (nextpos == j)
							{
								continue;
							}
							uint posMoveTo=hash_func[nextpos % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[nextpos]);
							hashentryP * subhashMoveto = HashTab[nextpos];
							bool *Groupmask = bitsetGrpPtr[nextpos];
							if (Groupmask[posMoveTo] == false)//have a empty position
							{
								//find hashTables has minimum loading factor
								{
									int indexMinLoading = nextpos;
									int NumLoadingMin = NumLoading[nextpos];
									int LenHashTabMin = hashlen[nextpos]; //length of Hash Tab with minimum Loading
									for (int idex = nextpos+1 ; idex < NumStages ; idex++)
									{
										uint posMoveToA=hash_func[idex % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[idex]);
										bool *GroupmaskA = bitsetGrpPtr[idex];
										if (GroupmaskA[posMoveToA] == false)
										{
											if (1.0*NumLoading[idex]/hashlen[idex] < 1.0*NumLoadingMin/LenHashTabMin) //find a bucket in a hash table with less loadings
											{
												NumLoadingMin = NumLoading[idex]; 
												LenHashTabMin = hashlen[idex];
												indexMinLoading = idex;
											}
										}
									}
									//insert into hash table with minimum loading 
									if (indexMinLoading != nextpos)
									{
										nextpos = indexMinLoading;
										//change corresponding points
										posMoveTo=hash_func[nextpos % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[nextpos]);
										subhashMoveto = HashTab[nextpos];
										Groupmask = bitsetGrpPtr[nextpos];
									}
									
								}
								//mask corresponding bit
								Groupmask[posMoveTo] = true;
								//increase corresponding number of loaded buckets by 1
								NumLoading[nextpos]++;
								//kick it
								insertMAtot++;
								subhashMoveto[posMoveTo].value = subhash[pos].value;
								memcpy(subhashMoveto[posMoveTo].key, subhash[pos].key, lentokick);
								//move the node on the linked chain to the position where the kicked node residues
								subhash[pos].value = node->value;
								memcpy(subhash[pos].key, node->key, len+1);
								//delete node
								subhashlast[i].next = node->next;
								delete node;
								NumSigLikedChain[i]--;
								kicked = true; //kick successful
								NumCollisions--;
								break;
							}
						}
						if (kicked == true)
						{
							break;
						}
					}
				
				if (kicked == true)
				{
#ifdef _DEBUG
					if (i == 39606)
					{
						printf("39606 found!\n");
					}
#endif
					//counter for items kicked successfully is increased by 1
					NumKicked++;
					//handle Pointer to End of chain
					if (subhashlast[i].next == NULL)
					{
						pEnd[i] = &(subhashlast[i]);
					}
					continue;
				}
				else
				{
#ifdef _DEBUG
					if(i == 26)
					{

						printf("Find i = 26\n");
					}
#endif
					//create extra Node
					extraNode = subhashlast[i].next;
					extraNode->IsKICKED = true;
					state = STATE_BLIND_KICK;
					//printf("blind kick: %d\n",i);
					subhashlast[i].next = extraNode->next;

					//Update Pointer to ENDNODE
					if (extraNode->next == NULL) //We take out ENDNODE
					{
						pEnd[i] = &(subhashlast[i]);
					}
					extraNode->next = NULL;
#ifdef _DEBUG
					if (memcmp(extraNode->key,"2.189.64.0/22", 13) == 0)
					{
						printf("found in chain\n");
					}
#endif
					NumSigLikedChain[i]--;
					StageToTry = 0; //Try from the first hash Table

				}
					
				
			}
			else if(state  == STATE_BLIND_KICK)
			{
#ifdef _DEBUG
				printf("Number of Collisions before \t%d th blind kick is:\t%d\n", StageToTry+1, NumCollisions);
#endif 

				//swap extranode with subhash[stagetry][pos]
				int lenExtra=strlen((const char *)(extraNode->key));
				uint posSwap = hash_func[StageToTry % HASH_NUM_MAX]((const unsigned char *)(extraNode->key) , lenExtra ) % (hashlen[StageToTry]);
				char keyMiddle[KEYLENGTH];
				int valMiddle;
				//copy from extra node to the middle space
				memcpy(keyMiddle, extraNode->key, lenExtra+1);
				valMiddle = extraNode->value;
				//copy from nodeToSwap To extra node
				hashentryP * subhash = HashTab[StageToTry];
				insertMAtot++;
				int lenswap = strlen((const char *)(subhash[posSwap].key));
				memcpy(extraNode->key, subhash[posSwap].key, lenswap+1);
				extraNode->value = subhash[posSwap].value;
				//copy from the middle space to the node to swap
				memcpy(subhash[posSwap].key, keyMiddle, lenExtra+1);
				subhash[posSwap].value = valMiddle;

				
				bool kicked = false;
				//find a position in sub hash tables
				for( int  j = 0 ; j < NumStages ; j++)
				{
					if (j == StageToTry)
					{
						continue;
					}
					uint pos=hash_func[j % HASH_NUM_MAX]((const unsigned char *)(extraNode->key) , lenswap ) % (hashlen[j]);

					hashentryP * subhash = HashTab[j];
					insertMAtot++;
					char *keytokick = (char *) subhash[pos].key;
					int lentokick=strlen((const char *)(keytokick));
					for (int nextpos = 0; nextpos < NumStages ;nextpos++)
					{
						if (nextpos == j) //Doesn't need to kick a node to the same position of original one
						{
							continue; 
						}
						
						uint posMoveTo=hash_func[nextpos % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[nextpos]);
						hashentryP * subhashMoveto = HashTab[nextpos];
						bool *Groupmask = bitsetGrpPtr[nextpos];
						if (Groupmask[posMoveTo] == false)//have a empty position
						{
							//find out the hashTable which has minimum loading factor
							int indexMinLoading = nextpos;
							int NumLoadingMin = NumLoading[nextpos];
							int LenHashTabMin = hashlen[nextpos]; //length of Hash Tab with minimum Loading
							for (int idex = nextpos+1 ; idex < NumStages ; idex++)
							{
								uint posMoveToA=hash_func[idex % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[idex]);
								bool *GroupmaskA = bitsetGrpPtr[idex];
								if (GroupmaskA[posMoveToA] == false)
								{
									if (1.0*NumLoading[idex]/hashlen[idex] < 1.0*NumLoadingMin/LenHashTabMin) //find a bucket in a hash table with less loadings
									{
										NumLoadingMin = NumLoading[idex]; 
										LenHashTabMin = hashlen[idex];
										indexMinLoading = idex;
									}
								}
							}
							//insert into hash table with minimum loading 
							if (indexMinLoading != nextpos)
							{
								nextpos = indexMinLoading;
								//change corresponding points
								posMoveTo=hash_func[nextpos % HASH_NUM_MAX]((const unsigned char *)(keytokick) , lentokick ) % (hashlen[nextpos]);
								subhashMoveto = HashTab[nextpos];
								Groupmask = bitsetGrpPtr[nextpos];
							}

							//mask corresponding bit
							Groupmask[posMoveTo] = true;
							//increase corresponding number of loaded buckets by 1
							NumLoading[nextpos]++;
							//kick it
							insertMAtot++;
							subhashMoveto[posMoveTo].value = subhash[pos].value;
							memcpy(subhashMoveto[posMoveTo].key, subhash[pos].key, lentokick+1);
							//move the node on the linked chain to the position where the kicked node residues
							subhash[pos].value = extraNode->value;
							memcpy(subhash[pos].key, extraNode->key, lenswap+1);
							//delete extranode
							delete extraNode;
							kicked = true; //kick successful
							break;
						}
						
					}
					if (kicked == true)
					{
						break;
					}
				}

				if (kicked == true) //failed to blind_kick
				{
					//counter for items blindkicked successfully is increased by 1
					NumBlindKickSucc++;

					NumCollisions--;
					state = STATE_KICK;
				}
				else //false
				{
					if (StageToTry < blind_kick_num-1 && StageToTry < NumStages-2) //NumStages -2 == No.-2
					{
						StageToTry++;
					}
					else //have used all chances of blind kicks
					{
#ifdef _DEBUG

						if (memcmp(extraNode->key,"2.189.64.0/22", 13) == 0)
						{
							printf("found in chain\n");
						}
#endif
						//counter for items blindkicked failed is increased by 1
						NumBlindKickFail++;
						//append extranode to the last table
						int len = strlen((const char *)(extraNode -> key));
						uint pos=hash_func[NumStages-1 % HASH_NUM_MAX]((const unsigned char *)(extraNode->key) , len ) % (hashlen[NumStages-1]);
						hashentryP* lastsubhash = HashTab[NumStages-1];
#ifdef _DEBUG
						if (pos == 39606)
						{
							printf("Find 39606\n");
						}
#endif
						if (extraNode->IsKICKED == true) //if Iskicked, Insert into the end of singly linked chain
						{
							pEnd[pos]->next = extraNode;
							pEnd[pos] = pEnd[pos]->next;
						}
						else //Insert into the head of the singly linked chain
						{
							if (subhash[pos].next == NULL) //update pointer to END node
							{
								pEnd[pos] = extraNode;
							}
							extraNode->next = subhash[pos].next;
							subhash[pos].next =  extraNode;							
							extraNode = NULL;
			
						}

						NumSigLikedChain[pos]++;
						printf("kicked failed\n");
						state = STATE_KICK;
					}
				}

			}
				
			
		}
	}


	}
	
	//insert items into bloom filter
	for( int i = 0 ; i < NumStages; i++)
	{
		hashentryP * subhash = HashTab[i];
		insertMAtot++;
		int indexBF;
		if ( i < NumGroups)
		{
			indexBF = i+1; //indexBF starts from 1
		}
		else
		{
			indexBF = (NumStages - i - 1) + 1; //indexBF starts from 1
		}
		
		for(int j = 0 ; j < hashlen[i]; j++)
		{
			insertMAtot++;
			if (subhash[j].value != 0)
			{
#ifdef _DEBUG
				if (memcmp(subhash[j].key,"2.189.64.0/22", 13) == 0)
				{
					printf("found!\n");
				}
#endif
				int len=strlen((const char *)(subhash[j].key));
				mulbitBF->insert(subhash[j].key , len, indexBF);

				if ( i >= NumGroups) // lower part hash tale
				{

					lowPartBF->insert(subhash[j].key, len);
				}
			}
			if( i == NumStages-1) // last hash table
			{
				//check singly linked chain
				hashentryP * subhash = HashTab[NumStages-1];
				hashentryP* node = subhash[j].next; //head node of chain
				insertMAtot++;
				while (node != NULL)
				{
#ifdef _DEBUG
					if (memcmp(node->key,"2.189.64.0/22", 13) == 0)
					{
						printf("found in chain\n");
					}
#endif
					int len=strlen((const char *)(node->key));
					mulbitBF->insert(node->key , len, indexBF);

					if ( i >= NumGroups) // lower part hash tale
					{

						lowPartBF->insert(node -> key, len);
					}

					node  = node -> next;
				}
			}
			

		}

	}
	delete [] pEnd;
	return true;
}


bool RTBHash::insert(char * key , int val)
{
	//insert count from 1 to MEMORY_ACC_UNIT 
	if (insertCount < MEMORY_ACC_UNIT)
	{
		insertCount++;
	}
	else
	{
		insertCount = 1;
		insertMemAcc[insertMAcurpos] =(0.0+insertMAtot)/MEMORY_ACC_UNIT;
		insertMAcurpos++;
		insertMAtot = 0;
	}

	//try to insert key intro the main table
	int len=strlen((const char *)(key));


	//find a position in sub hash tables
	for( int  i = 0 ; i < NumStages ; i++)
	{
		uint pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);

		hashentryP * subhash = HashTab[i];
		if (subhash[pos].value == 0 )
		{
			insertMAtot++;

			memcpy(subhash[pos].key ,key,len);
			subhash[pos].value = val;
			subhash[pos].next = NULL;

			//mask corresponding bit
			bool *groupPtr = bitsetGrpPtr[i];
			groupPtr[pos] = true;

			return true;
		}

	}

	//can not find a empty slot to store the key 
	NumCollisions++;

	//store it in the singly linked chain of last hash table
	uint pos  = hash_func[NumStages-1 % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[NumStages-1]);
	//insert in the head of singly linked chain
	hashentryP * subhash = HashTab[NumStages-1];
	hashentryP *TempPtr = new hashentryP;
	TempPtr->next = subhash[pos].next;
	subhash[pos].next = TempPtr;
	insertMAtot++;

	TempPtr -> value  = val;
	memcpy( TempPtr->key , key , len);
	//update the number of corresponding singly linked chain
	NumSigLikedChain[pos]++;

	return true;
}


bool RTBHash::search(char *key, int & val)  
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

	bool  inLowerPart = lowPartBF->query((const unsigned char *)key, len);
	uchar ret = mulbitBF->query((const unsigned char *) key, len );
	uchar tmp = ret;
	for(int i = 0 ; i < NumGroups; i++)
	{
		if((tmp & 0x80) != 0) // in this groups
		{
			if(inLowerPart == true)
			{
				//search lower part first
				uint pos=hash_func[(NumStages-i-1) % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[NumStages-i-1]);
				hashentryP * subhash = HashTab[NumStages-i-1];
				searchMAtot ++;
				if(memcmp(subhash[pos].key , key , len) == 0)
				{
					val = subhash[pos].value;
					return true;
				}
				//if it's the last tab
				if ( i == 0)
				{
					hashentryP* hashptr = subhash[pos].next;
					for ( ; hashptr != NULL ; hashptr = hashptr -> next)
					{
						searchMAtot++;
						if(memcmp(hashptr->key , key , len) == 0)
						{
							val = hashptr -> value;
							return true;
						}
					}
				}
			}

			 //search upper part 
			{
				//search upper part
				uint pos=hash_func[i % HASH_NUM_MAX]((const unsigned char *)(key) , len ) % (hashlen[i]);
				hashentryP * subhash = HashTab[i];
				searchMAtot ++;
				if(memcmp(subhash[pos].key , key , len) == 0)
				{
					val = subhash[pos].value;
					return true;
				}
			}
			
		}
		
		tmp = tmp << 1;
	}	
	//can not find this key 
		return false;

	
}

void RTBHash::collect(void)
{
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	int *tot;
	tot = new int[NumStages];
	memset(tot , 0 , NumStages*sizeof(int));
	
	
	for(int i = 0; i < NumStages; i++)
	{
		hashentryP* hashtab = HashTab[i];
		for(int j = 0; j < hashlen[i] ; j++)
		{
			if( hashtab[j].value != 0) tot[i]++;
			//if( i == NumStages-1) tot[i]+= NumSigLikedChain[i]; //add nodes in singly linked chain
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

void RTBHash::report(char *outputfile)
{
	FILE *file = fopen(outputfile, "w");
	if (!file)
	{
		printf("file %s cannot be read!\n", outputfile);
	}
	collect();
	printf("LoadingFactor/Collisions_nokick/NumCollisions-after-%d-blind-kicks: \t%f\t%d\t%d\n", blind_kick_num, loadingfactorT,Collisions_nokick, NumCollisions);
	fprintf(file,"LoadingFactor/Collisions_nokick/NumCollisions-after-%d-blind-kicks: \t%f\t%d\t%d\n", blind_kick_num, loadingfactorT,Collisions_nokick, NumCollisions); // yt: we need collision rate.
	
	printf("Collisions_nokick=\t%d\n", Collisions_nokick);
	fprintf(file, "Collisions_nokick=\t%d\n", Collisions_nokick);
	
	printf("NumKICKED/NumBlindKickedSucc/NumBlindKickedFail:\t%d\t%d\t%d\n", NumKicked, NumBlindKickSucc,NumBlindKickFail);
	fprintf(file, "NumKICKED/NumBlindKickedSucc/NumBlindKickedFail:\t%d\t%d\t%d\n", NumKicked, NumBlindKickSucc,NumBlindKickFail);
	for(int i = 0 ; i < NumStages ; i++)
	{
		printf("LoadingFactor%d: %f\n",i , loadingfactor[i]);
		fprintf((FILE *)file,"LoadingFactor%d: \t%f\n",i , loadingfactor[i]);
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

bool RTBHash::reset()
{
	Collisions_nokick=0;
	//Count for search insert and remove operation
	searchCount = 0;
	insertCount = 0;
	removeCount = 0;

	//XXXMemAcc is a array contains the average memory access times over 100 operations of XXX
	memset(searchMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(float));
	memset(removeMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(float));
	memset(insertMemAcc, 0, MEMORY_ACC_POINTER_MAX*sizeof(float));


	//XXXMAcurpos is a integer represents the index of the leftmost unused slot in XXXMemAcc
	searchMAcurpos = 0;
	insertMAcurpos = 0;
	removeMAcurpos = 0;

	//XXXMAtot is a temporal variable represents the sum of  Memory access times before, which will be reset after MEMORY_ACC_UNIT times operations
	searchMAtot = 0;
	insertMAtot = 0;
	removeMAtot = 0;
	//reset counter
	NumKicked = 0; //number of items kicked successfully
	NumBlindKickSucc = 0; //number of item blindly kicked successfully
	NumBlindKickFail = 0; //number of item blindly kicked failed
	return true;
}

bool RTBHash::test(char *File)
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
		
		int retvalue = 0;
		bool ret = search(key, retvalue);
		if((ret == false) || (retvalue != value)) 
		{
			nofound++;
			hashentryP* psubhash = HashTab[0];
			printf("%s, %d, %d\n , false:%d",key, value ,retvalue, ret == false? 1 : 0);
			bool retB = search(key, retvalue);

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