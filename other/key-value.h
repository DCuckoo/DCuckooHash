//#ifndef KEY_VALUE_H
//#define KEY_VALUE_H

#pragma once


#define KEY_SIZE 18
#define COUNT 8

#define KICK_COUNT_MAX 500

#define MEMORY_ACC_UNIT 10000
#define MEMORY_ACC_POINTER_MAX 10000


struct hashentry
{
	int value;
	unsigned char key[KEY_SIZE]; 
};

struct hashentryP
{

	int value;
	unsigned char key[KEY_SIZE]; 
	struct hashentryP * next;
	bool IsKICKED;
};

struct aCounter
{
	bool bit1:1;
#if COUNT>1
	bool bit2:1;
#if COUNT>2
	bool bit3:1;
#if COUNT>3
	bool bit4:1;
#if COUNT>4
	bool bit5:1;
#if COUNT>5
	bool bit6:1;
#if COUNT>6
	bool bit7:1;
#if COUNT>7
	bool bit8:1;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
};

hashentry * readHashEntries(int & readline, char *inputfile);
hashentryP *  readHashEntriesPointer(int & readline, char *inputfile);
int getFIBSize(char * fibfile);

//#endif