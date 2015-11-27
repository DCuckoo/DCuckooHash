#include "key-value.h"

#include <stdlib.h>
#include <iostream>
#include <fstream>

int getFIBSize(char * fibfile)
{
	int readlines=0;
	char key[20];
	int val=0;

	FILE *fp = fopen(fibfile,"r");
	if (NULL == fp)
	{
		printf("open %s failed", fibfile);
		return NULL;
	}
	while(!feof(fp))
	{
		fscanf(fp, "%s %u", key, &val);
		if (strlen(key)>4)readlines++;
	}
	fclose(fp);	

	return readlines;
}

hashentry * readHashEntries(int & readline, char *inputfile)
{
	hashentry *pHashentries=new hashentry[1000000];
	memset(pHashentries,0,sizeof(hashentry)*1000000);

	char *hashfile=inputfile;
	FILE *fp = fopen(hashfile,"r");
	if (NULL == fp)
	{
		printf("open %s failed", hashfile);
		return NULL;
	}
	while(!feof(fp))
	{
		fscanf(fp, "%s %u", pHashentries[readline].key, &(pHashentries[readline].value));
		if (strlen((const char *)(pHashentries[readline].key))>4)readline++;
	}
	fclose(fp);	



	return pHashentries;
}

hashentryP *  readHashEntriesPointer(int & readline, char *inputfile)
{
	hashentryP *pHashentries=new hashentryP[1000000];
	memset(pHashentries,0,sizeof(hashentryP)*1000000);

	char *hashfile=inputfile;
	FILE *fp = fopen(hashfile,"r");
	if (NULL == fp)
	{
		printf("open %s failed", hashfile);
	}
	while(!feof(fp))
	{
		fscanf(fp, "%s %u", pHashentries[readline].key, &(pHashentries[readline].value));
		if (strlen((const char *)(pHashentries[readline].key))>4)readline++;
	}
	fclose(fp);	

	return pHashentries;
}