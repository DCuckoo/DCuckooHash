//该程序是rectangleBF的源码
#include<stdio.h>
#include<stdlib.h>
#include <iostream>
#include <windows.h>
#include <time.h>
#include <math.h>
#include "key-value.h"
#include "std_bf.h"
#include <fstream>
#include "hash_function.h"
#include "PeacockHash.h"
#include "dleftHash.h"
#include "DoubleHash.h"
#include "LinearHash.h"
#include "LinkHash.h"
#include "RTBHash.h"
#include "cuckooHash.h"

#define HT_STAGE_NUM 6

#define HASH_ENTRY_MAX 500000

#include "md5.h"
#include "sha1.h"

using namespace std;


bool linkExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		LHash aHashtable;
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.link.init", fibfile);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.link.search", fibfile);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;
}

bool linearExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		LinearHash aHashtable;
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.linear.init", fibfile);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.linear.search", fibfile);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;
}

bool doubleExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		DHash aHashtable;
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.double.init", fibfile);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.double.search", fibfile);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;

}

bool cuckooExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		cuckooHash aHashtable;
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char * fibfileShort=&(fibfile[4]);
		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.cuckoo%.2f.init", fibfileShort, ht_times);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.cuckoo%.2f.search", fibfileShort,ht_times);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		//aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;
}

bool peacockExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		PeacockHash aHashtable; 
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.peacock.init", fibfile);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.peacock.search", fibfile);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;
}

bool dleftExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times)
{
	try
	{
		int fiblen=getFIBSize(fibfile);
		dleftHash aHashtable; 
		cout << "successful initial" <<endl;

		printf("\n\nStart to process %s...\n", fibfile);

		char outputfileInit[100];
		memset(outputfileInit, 0, sizeof(outputfileInit));
		sprintf(outputfileInit, "%s.dleft.init", fibfile);

		char outputfileSearch[100];
		memset(outputfileSearch, 0, sizeof(outputfileSearch));
		sprintf(outputfileSearch, "%s.dleft.search", fibfile);

		aHashtable.initialFromFile(fibfile, ht_times);

		//test the correctness of initialFromFile
#ifdef _DEBUG
		if(aHashtable.test(fibfile) == true)
		{
			printf("Congratulation! pass test!\n");
		}
		else
		{
			printf("not pass test");
		}
#endif 
		aHashtable.report(outputfileInit);

		//read the traffic, then search the hash table.
		FILE * fp_traffic =fopen(trafficfile,"r");
		if (NULL == fp_traffic)  //If FilePtr is NULL
		{
			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
			return false;
		}

		printf("\nstart traffic query...\n");
		char key[KEYLENGTH];
		memset(key , 0 , sizeof(key));
		int readlines=0;
		int val=0;
		while(!feof(fp_traffic))
		{
			fscanf(fp_traffic, "%s", key);
			readlines++;
			aHashtable.search((const unsigned char *)key, val);
			if (readlines%1000==0)
			{
				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
			}
		}
		printf("val=%d\n",val);
		printf("\nafter the traffic query...\n");
		aHashtable.report(outputfileSearch);
	}
	catch(char *s)
	{
		fprintf(stderr, "error: %s\n",s);
	}

	printf("Congrats! Traffic query is completed!\n");
	return true;

}

//int RectExperiments(char * fibfile, char * trafficfile, char * updatefile, float ht_times, int blind_kick_num)
//{
//	try
//	{
//		//473611,  (a+a+7*5000)*4=
//		int fiblen=getFIBSize(fibfile);
//		RTBHash aHashtable;
//		aHashtable.blind_kick_num=blind_kick_num;
//		cout << "successful initial" <<endl;
//
//		printf("\n\nStart to process %s...\n", fibfile);
//
//		char * fibfileShort=&(fibfile[4]);
//
//		char outputfileInit[100];
//		memset(outputfileInit, 0, sizeof(outputfileInit));
//		sprintf(outputfileInit, "%s.rect%d_%.2f.init", fibfileShort, aHashtable.blind_kick_num, ht_times);
//
//		char outputfileSearch[100];
//		memset(outputfileSearch, 0, sizeof(outputfileSearch));
//		sprintf(outputfileSearch, "%s.rect%d_%.2f.search", fibfileShort, aHashtable.blind_kick_num, ht_times);
//
//		aHashtable.initialFromFile(fibfile, ht_times);
//
//		printf("\nafter %d Blind kick\n", aHashtable.blind_kick_num);
//		aHashtable.report(outputfileInit);
//		return 1;
//	
//		//read the traffic, then search the hash table.
//		FILE * fp_traffic =fopen(trafficfile,"r");
//		if (NULL == fp_traffic)  //If FilePtr is NULL
//		{
//			fprintf(stderr , "fibfile %s open failed!\n", trafficfile);
//			return -1;
//		}
//
//		//test the correctness of initialFromFile
//#ifdef _DEBUG
//		if(aHashtable.test(fibfile) == true)
//		{
//			printf("Congratulation! pass test!\n");
//		}
//		else
//		{
//			printf("not pass test");
//		}
//#endif 
//
//		printf("\nstart traffic query...\n");
//		char key[KEYLENGTH];
//		memset(key , 0 , sizeof(key));
//		int readlines=0;
//		int val=0;
//		while(!feof(fp_traffic))
//		{
//			fscanf(fp_traffic, "%s", key);
//			readlines++;
//			aHashtable.search(key, val);
//			if (readlines%1000==0)
//			{
//				printf("\r%.2f%%", 100.0*readlines/fiblen/10);
//			}
//		}
//		printf("val=%d\n",val);
//		printf("\nafter the traffic query...\n");
//		aHashtable.report(outputfileSearch);
//	}
//	catch(char *s)
//	{
//		fprintf(stderr, "error: %s\n",s);
//	}
//
//	printf("Congrats! Traffic query is completed!\n");
//	return 1;
//}


void main(int argc, char* argv[])
{
	//main_hashCollisionTest(argc, argv); 

	char inputfile[100];
	memset(inputfile, 0, sizeof(inputfile));
	if (argc>3)
	{
		strcpy(inputfile,argv[1]);
	}
	else       
	{
		printf("Error parameters, the format should be: algorithmName, fibfile, trafficfile, updatefile\n"); // times, blind kick
		return;
	}
	
	     //if (!strcmp(argv[1], "RHT"))       RectExperiments(argv[2], argv[3], "",atof(argv[4]), atoi(argv[5]));//argv[4], ht_times);
	     if (!strcmp(argv[1], "peacock"))   peacockExperiments(argv[2], argv[3],  "",atof(argv[4]));//argv[4], ht_times);
	else if (!strcmp(argv[1], "dleft"))     dleftExperiments(argv[2], argv[3],  "",atof(argv[4]));//argv[4], ht_times);
	else if (!strcmp(argv[1], "linear"))    linearExperiments(argv[2], argv[3],  "",atof(argv[4]));//argv[4], ht_times);
	else if (!strcmp(argv[1], "link"))      linkExperiments(argv[2], argv[3],  "",atof(argv[4]));//argv[4], ht_times);
	else if (!strcmp(argv[1], "double"))    doubleExperiments(argv[2], argv[3], "",atof(argv[4]));//argv[4], ht_times);
	else if (!strcmp(argv[1], "cuckoo"))    cuckooExperiments(argv[2], argv[3], "",atof(argv[4]));//argv[4], ht_times);
	else printf("error input! wrong algorithm name, program exits...\n");
}