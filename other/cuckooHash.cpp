#include "cuckooHash.h"


cuckooHash::cuckooHash(void)
{
}


cuckooHash::~cuckooHash(void)
{
	delete [] loadingfactor;

	for (int i = 0; i< 2; i++)
	{
		hashentry *subHashTab = HashTab[i];
		delete [] subHashTab;
	}

	delete [] HashTab;

	hashentryP *PtrA = singlyLinkedChain;
	hashentryP *PtrB = singlyLinkedChain;
	while (PtrA != NULL)
	{
		PtrB = PtrA->next; // save the pointer to the next node
		delete PtrA; //delete current node
		PtrA = PtrB; //let PtrA direct the nextnode
	}

}

/*
	lenHashTab: Total length of two hash tables
	indexHashFunc1: index of Hash Func1
	indexHashFunc2: index of Hash Func2
	*/
cuckooHash::cuckooHash(unsigned int lenHashTab, unsigned int indexHashFunc1 , unsigned int indexHashFunc2)
{
	if (lenHashTab <= 1)
	{
		throw("Length of two hash tables must larger than 1");
	}

	if (lenHashTab%2 != 0)
	{
		fprintf(stderr, "warning:total length of two hash tab is not a even number, so we will round it down to the nearest even number\n");
		lenHashTab = lenHashTab-1;
	}
	if (indexHashFunc1 >= HASH_NUM_MAX)
	{
		indexHashFunc1  = indexHashFunc1 % HASH_NUM_MAX;
	}
	if (indexHashFunc2 >= HASH_NUM_MAX)
	{
		indexHashFunc2 =  indexHashFunc2 % HASH_NUM_MAX;
	}
	if (indexHashFunc1 == indexHashFunc2)
	{
		throw("error:You should use two different hash functions\n");
	}

	//initial hash functions used in cockoo hash
	cockooHashFunc[0] = hash_func[indexHashFunc1];
	cockooHashFunc[1] = hash_func[indexHashFunc2];


	totsize = lenHashTab; //total size of hash table
	lenPerTab = lenPerTab/2; //length of a hash table
	//initial hash table
	HashTab = new hashentry*[2];
	for (int i = 0; i< 2; i++)
	{
		hashentry *subHashTab = HashTab[i];
		subHashTab = new hashentry[lenPerTab];
		memset(subHashTab, 0 , lenPerTab*sizeof(hashentry));
	}
	//initial singly Linked Chain
	singlyLinkedChain = NULL; //singly linked chain for hashentryP

	NumCollisions = 0;
	loadingfactor = new float[2]; //loading factor of each table
	memset(loadingfactor, 0, 2*sizeof(float));

	loadingfactorT = 0; //loading factor of total hash tables
	lenSLChain = 0;
	reset(); //reset counter
}

	/*
	NumElements: number of elements to insert
	indexHashFunc1: index of Hash Func1
	indexHashFunc2: index of Hash Func2
	*/
cuckooHash::cuckooHash(unsigned int NumElements, float ht_times, unsigned int indexHashFunc1 , unsigned int indexHashFunc2)
{
	if (ht_times <= 0)
	{
		throw("ht_times must be larger than 0\n");
	}
	if (NumElements == 0)
	{
		throw("Number of elements to insert must be larger  than 0");
	}
	unsigned int LenHashTab =(unsigned int) NumElements*ht_times;
	cuckooHash(LenHashTab, indexHashFunc1, indexHashFunc2 );

}
	/*
	initial hash table using entries from InputFile
	*/
	/*
	ht_times: the ratio of length of two hash tables and the number of elements to insert
	indexHashFunc1: index of Hash Func1
	indexHashFunc2: index of Hash Func2
	*/
bool cuckooHash::initialFromFile(char *InputFileName, float ht_times,  unsigned int indexHashFunc1 , unsigned int indexHashFunc2)
{
	//initial Hash Table
	int lines=0;
	//get number of lines of inputfile
	hashentryP * pHashentries=readHashEntriesPointer(lines, InputFileName);
	//initial hash tables
	if (ht_times <= 0)
	{
		throw("ht_times must be larger than 0\n");
	}
	if (lines == 0)
	{
		throw("Number of elements to insert must be larger  than 0");
	}
	unsigned int lenHashTab =(unsigned int) lines*ht_times;
	

	if (lenHashTab%2 != 0)
	{
		fprintf(stderr, "warning:total length of two hash tab is not a even number, so we will round it down to the nearest even number\n");
		lenHashTab = lenHashTab-1;
	}
	if (indexHashFunc1 >= HASH_NUM_MAX)
	{
		indexHashFunc1  = indexHashFunc1 % HASH_NUM_MAX;
	}
	if (indexHashFunc2 >= HASH_NUM_MAX)
	{
		indexHashFunc2 =  indexHashFunc2 % HASH_NUM_MAX;
	}
	if (indexHashFunc1 == indexHashFunc2)
	{
		throw("error:You should use two different hash functions\n");
	}


	//initial hash functions used in cockoo hash
	cockooHashFunc[0] = hash_func[indexHashFunc1];
	cockooHashFunc[1] = hash_func[indexHashFunc2];


	totsize = lenHashTab; //total size of hash table
	lenPerTab = lenHashTab/2; //length of a hash table
	//initial hash table
	HashTab = new hashentry*[2];
	for (int i = 0; i< 2; i++)
	{
		
		HashTab[i] = new hashentry[lenPerTab];
		hashentry *subHashTab = HashTab[i];
		memset(subHashTab, 0 , lenPerTab*sizeof(hashentry));
	}
	//initial singly Linked Chain
	singlyLinkedChain = NULL; //singly linked chain for hashentryP

	NumCollisions = 0;
	loadingfactor = new float[2]; //loading factor of each table
	memset(loadingfactor, 0, 2*sizeof(float));

	loadingfactorT = 0; //loading factor of total hash tables

	reset(); //reset counters
	//initial completely

	for (int i=0; i<lines; i++)
	{
		insert((char *)pHashentries[i].key, pHashentries[i].value);
	}

	if(pHashentries)delete []pHashentries;
	return true;
}
	/*
	key: a key to insert
	val: the corresponding value of key
	if insert successfully, this function will return true, 
	else it will return false;
	stage: Number of stages. Default parameter is 8.
	*/
bool cuckooHash::insert(char * key , int val)
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

	/*
	int retval;
	if (search((const unsigned char *)key , retval))
	{
		if (retval == val)
		{
			return true; //this key and value pairs exist in the hash table
		}
	}
	*/
	int count = MAX_KICK_TIMES;
	
	hashentry temp;
	memset(&temp, 0, sizeof(temp));
	int len  = strlen((const char *) key);
	memcpy(temp.key, key, len+1 );
	temp.value = val;

	
	
	int index = 0;
	hashentry * subHashTab = HashTab[index];
	while (count > 0)
	{
		int len = strlen((const char *)temp.key);
		int pos = cockooHashFunc[index]((const unsigned char *)temp.key, len) % lenPerTab; //find the positon in the first hash tab;
		insertMAtot++;
		swap(&temp , &(subHashTab[pos]));
		if (temp.value == 0)
		{
			return true;
		}
		index = (index+1)%2; // update index
		subHashTab = HashTab[index]; // update subHashTab
		count--;
	}
	NumCollisions++;

#ifdef _DEBUG
	//append the temp node to the head of the singly lined chain
	hashentryP *newNode = new hashentryP;
	memset(newNode, 0 ,sizeof(hashentryP));
	len =  strlen((const char *)temp.key);
	memcpy(newNode->key, temp.key, len+1);
	newNode->value = temp.value;
	newNode->next = singlyLinkedChain;
	singlyLinkedChain = newNode;
#endif

	return true;
}
inline void cuckooHash::swap(hashentry* entryA, hashentry* entryB)
{
	hashentry entryTemp;
	int lenA = strlen((const char *)entryA->key);
	int lenB = strlen((const char *)entryB->key);
	memcpy(entryTemp.key, entryA->key, lenA+1);
	entryTemp.value = entryA->value;
	memcpy(entryA->key , entryB->key, lenB+1);
	entryA->value = entryB->value;
	memcpy(entryB->key, entryTemp.key, lenA+1);
	entryB->value = entryTemp.value;

}
bool cuckooHash::search(const unsigned char *key, int & val)  //search for a key, but return its value in the hash table
{
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

	for (int index = 0 ;index <= 1; index ++)
	{
		hashentry *subHashTab = HashTab[index];
		int len = strlen((const char *) key);
		int pos = cockooHashFunc[index]((const unsigned char *)key, len) % lenPerTab; //find the positon in the first hash tab;
		
		searchMAtot++;
		if (memcmp(subHashTab[pos].key, key, len) == 0) //equal
		{
			val = subHashTab[pos].value;
			return true;
		}
	}

#ifdef _DEBUG
	//can not find this node in HashTab
	//So we try to search in the singly linked chain
	hashentryP *node = singlyLinkedChain;
	while (node != NULL)
	{

		int len = strlen((const char *) key);
		if (memcmp(node->key, key, len) == 0) //equal
		{
			val = node->value;
			return true;
		}
		node = node->next;
	}
#endif

	return false; //can not find this in node
}



bool cuckooHash::remove(char *key) //remove a key from hash table
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


	for (int index = 0 ;index <= 1; index ++)
	{
		hashentry *subHashTab = HashTab[index];
		int len = strlen((const char *) key);
		int pos = cockooHashFunc[index]((const unsigned char *)key, len) % lenPerTab; //find the positon in the first hash tab;
		
		removeMAtot++;
		if (memcmp(subHashTab[pos].key, key, len) == 0) //equal
		{
			subHashTab[pos].value = 0; //set value to 0
			return true;
		}
	}

	//can not find this node in HashTab
	//So we try to search in the singly linked chain
	hashentryP *node = singlyLinkedChain;
	while (node != NULL)
	{

		int len = strlen((const char *) key);
		if ((node->key, key, len) == 0) //equal
		{
			node->value = 0;
			return true;
		}
		node = node->next;
	}
	return false; //can not find this in node
}
void cuckooHash::collect(void) //collect informations about loading factor
{
	/*
	char empstr[KEYLENGTH];
	memset(empstr , 0 , KEYLENGTH);
	*/
	int *tot;
	tot = new int[2];
	memset(tot , 0 , 2*sizeof(int));
	for(int i = 0; i< 2 ; i++)
	{
		hashentry * subHashTab = HashTab[i];
		for ( int j = 0; j < lenPerTab; j++)
		{
			if(subHashTab[j].value != 0) //if the value of the node is 0, then this node is not occupied
				tot[i]++;
		}
		
	}
	
	
	int totT = 0;
	int tottab = 0;
	for( int i = 0; i < 2; i++)
	{
		totT += tot[i];
		tottab += lenPerTab;
		loadingfactor[i] = 1.0*tot[i] / lenPerTab;
	}
	loadingfactorT  = 1.0*totT/tottab;
	delete [] tot;
}
	/* report 
	loading factor , number of collisions and the ratio of the number
	of collsions to the total size of hash tables */
void cuckooHash::report(char *outputfile)
{
	FILE *file = fopen(outputfile, "w");
	collect();
	fprintf((FILE *)file,"CuckooHash\n");
	fprintf((FILE *)file,"LoadingFactor/NumCollisions: \t%f\t%d\n", loadingfactorT, NumCollisions); // yt: we need collision rate.
	for(int i = 0 ; i < 2 ; i++)
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
bool cuckooHash::reset()
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
bool cuckooHash::test(char *File)
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
			ret = search((const unsigned char *) key, retvalue);

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

