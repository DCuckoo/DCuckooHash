#include "hash_function.h"
#include "sha1.h"
#include "md5.h"
#include <string.h>


#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

unsigned int 
BOB(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 0;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int 
OAAT(const unsigned char *str, unsigned int len)
{
	unsigned int   hash, i;
	for (hash=0, i=0; i<len; ++i)
	{
		hash += str[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}


unsigned int 
Simple(const unsigned char * str, unsigned int len)
{
    unsigned int hash = 0;
	for(uint i = 0; i < len; i++){
		hash = hash * 33 + str[i];
	}    
    return hash;
}

unsigned int 
SBOX(const unsigned char * str, unsigned int len)
{
	unsigned int box[]={
	0xF53E1837, 0x5F14C86B, 0x9EE3964C, 0xFA796D53, 0x32223FC3, 0x4D82BC98, 0xA0C7FA62, 0x63E2C982,
    0x24994A5B, 0x1ECE7BEE, 0x292B38EF, 0xD5CD4E56, 0x514F4303, 0x7BE12B83, 0x7192F195, 0x82DC7300,
    0x084380B4, 0x480B55D3, 0x5F430471, 0x13F75991, 0x3F9CF22C, 0x2FE0907A, 0xFD8E1E69, 0x7B1D5DE8,
    0xD575A85C, 0xAD01C50A, 0x7EE00737, 0x3CE981E8, 0x0E447EFA, 0x23089DD6, 0xB59F149F, 0x13600EC7,
    0xE802C8E6, 0x670921E4, 0x7207EFF0, 0xE74761B0, 0x69035234, 0xBFA40F19, 0xF63651A0, 0x29E64C26,
    0x1F98CCA7, 0xD957007E, 0xE71DDC75, 0x3E729595, 0x7580B7CC, 0xD7FAF60B, 0x92484323, 0xA44113EB,
    0xE4CBDE08, 0x346827C9, 0x3CF32AFA, 0x0B29BCF1, 0x6E29F7DF, 0xB01E71CB, 0x3BFBC0D1, 0x62EDC5B8,
    0xB7DE789A, 0xA4748EC9, 0xE17A4C4F, 0x67E5BD03, 0xF3B33D1A, 0x97D8D3E9, 0x09121BC0, 0x347B2D2C,
    0x79A1913C, 0x504172DE, 0x7F1F8483, 0x13AC3CF6, 0x7A2094DB, 0xC778FA12, 0xADF7469F, 0x21786B7B,
    0x71A445D0, 0xA8896C1B, 0x656F62FB, 0x83A059B3, 0x972DFE6E, 0x4122000C, 0x97D9DA19, 0x17D5947B,
    0xB1AFFD0C, 0x6EF83B97, 0xAF7F780B, 0x4613138A, 0x7C3E73A6, 0xCF15E03D, 0x41576322, 0x672DF292,
    0xB658588D, 0x33EBEFA9, 0x938CBF06, 0x06B67381, 0x07F192C6, 0x2BDA5855, 0x348EE0E8, 0x19DBB6E3,
    0x3222184B, 0xB69D5DBA, 0x7E760B88, 0xAF4D8154, 0x007A51AD, 0x35112500, 0xC9CD2D7D, 0x4F4FB761,
    0x694772E3, 0x694C8351, 0x4A7E3AF5, 0x67D65CE1, 0x9287DE92, 0x2518DB3C, 0x8CB4EC06, 0xD154D38F,
    0xE19A26BB, 0x295EE439, 0xC50A1104, 0x2153C6A7, 0x82366656, 0x0713BC2F, 0x6462215A, 0x21D9BFCE,
    0xBA8EACE6, 0xAE2DF4C1, 0x2A8D5E80, 0x3F7E52D1, 0x29359399, 0xFEA1D19C, 0x18879313, 0x455AFA81,
    0xFADFE838, 0x62609838, 0xD1028839, 0x0736E92F, 0x3BCA22A3, 0x1485B08A, 0x2DA7900B, 0x852C156D,
    0xE8F24803, 0x00078472, 0x13F0D332, 0x2ACFD0CF, 0x5F747F5C, 0x87BB1E2F, 0xA7EFCB63, 0x23F432F0,
    0xE6CE7C5C, 0x1F954EF6, 0xB609C91B, 0x3B4571BF, 0xEED17DC0, 0xE556CDA0, 0xA7846A8D, 0xFF105F94,
    0x52B7CCDE, 0x0E33E801, 0x664455EA, 0xF2C70414, 0x73E7B486, 0x8F830661, 0x8B59E826, 0xBB8AEDCA,
    0xF3D70AB9, 0xD739F2B9, 0x4A04C34A, 0x88D0F089, 0xE02191A2, 0xD89D9C78, 0x192C2749, 0xFC43A78F,
    0x0AAC88CB, 0x9438D42D, 0x9E280F7A, 0x36063802, 0x38E8D018, 0x1C42A9CB, 0x92AAFF6C, 0xA24820C5,
    0x007F077F, 0xCE5BC543, 0x69668D58, 0x10D6FF74, 0xBE00F621, 0x21300BBE, 0x2E9E8F46, 0x5ACEA629,
    0xFA1F86C7, 0x52F206B8, 0x3EDF1A75, 0x6DA8D843, 0xCF719928, 0x73E3891F, 0xB4B95DD6, 0xB2A42D27,
    0xEDA20BBF, 0x1A58DBDF, 0xA449AD03, 0x6DDEF22B, 0x900531E6, 0x3D3BFF35, 0x5B24ABA2, 0x472B3E4C,
    0x387F2D75, 0x4D8DBA36, 0x71CB5641, 0xE3473F3F, 0xF6CD4B7F, 0xBF7D1428, 0x344B64D0, 0xC5CDFCB6,
    0xFE2E0182, 0x2C37A673, 0xDE4EB7A3, 0x63FDC933, 0x01DC4063, 0x611F3571, 0xD167BFAF, 0x4496596F,
    0x3DEE0689, 0xD8704910, 0x7052A114, 0x068C9EC5, 0x75D0E766, 0x4D54CC20, 0xB44ECDE2, 0x4ABC653E,
    0x2C550A21, 0x1A52C0DB, 0xCFED03D0, 0x119BAFE2, 0x876A6133, 0xBC232088, 0x435BA1B2, 0xAE99BBFA,
    0xBB4F08E4, 0xA62B5F49, 0x1DA4B695, 0x336B84DE, 0xDC813D31, 0x00C134FB, 0x397A98E6, 0x151F0E64,
    0xD9EB3E69, 0xD3C7DF60, 0xD2F2C336, 0x2DDD067B, 0xBD122835, 0xB0B3BD3A, 0xB0D54E46, 0x8641F1E4,
    0xA0B38F96, 0x51D39199, 0x37A6AD75, 0xDF84EE41, 0x3C034CBA, 0xACDA62FC, 0x11923B8B, 0x45EF170A
	};
	unsigned int hash = 0;
	for(uint i = 0; i < len; i++){
		hash ^= box[str[i]];
		hash *= 3;
	}
	return hash;
}
unsigned int 
TWMX( unsigned int a)
{
    a = (a ^ 61) ^ (a >> 16);
    a = a + (a << 3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

#include <stdint.h>
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

unsigned int 
Hsieh (const unsigned char * str, unsigned int len)
{
	unsigned int hash = len, tmp;
	int rem;

    //if (len <= 0 || str == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (str);
        tmp    = (get16bits (str+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        str  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (str);
                hash ^= hash << 16;
                hash ^= ((signed char)str[sizeof (uint16_t)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (str);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*str;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

unsigned int 
RSHash(const unsigned char * str, unsigned int len)
{
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;
	
	for(uint i = 0; i < len; i++){
		hash = hash * a + (*str++);
        a *= b;
	}
    //return (hash & 0x7FFFFFFF);
	return hash;
}

unsigned int 
JSHash(const unsigned char * str, unsigned int len)
{
	unsigned int hash = 1315423911;  
	for(uint i = 0; i < len; i++)  
	{  
		hash ^= ((hash << 5) + str[i] + (hash >> 2));  
	}  
	return hash;
}

unsigned int 
BKDR(const unsigned char * str, unsigned int len)
{	
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..  
    unsigned int hash = 0;  
	for(uint i = 0; i < len; i++)  
	{  
		hash = (hash * seed) + str[i]; 
	}
	
	return hash;
}

unsigned int 
DJBHash (const unsigned char * str, unsigned int len)
{
    unsigned int hash = 5381;
	for(uint i = 0; i < len; i++){
		hash += (hash << 5) + (*str++);
	}
    //return (hash & 0x7FFFFFFF);
	return hash;
}

unsigned int 
DEKHash(const unsigned char * str, unsigned int len)   
{   
    
    unsigned int hash = 1315423911;
	for(uint i = 0; i < len; i++){
		hash = ((hash << 5) ^ (hash >> 27)) ^ str[i];
	}
	
    return hash;
}

// AP Hash 
unsigned int 
APHash(const unsigned char *str, unsigned int len)
{
	unsigned int hash = 0;
	
 
	for (uint i = 0; i < len; i++)
	{
		if ((i & 1) == 0)
		{
			hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
		}
		else
		{
			hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
		}
	}
 
	//return (hash & 0x7FFFFFFF);
	return hash;
}

unsigned int 
CRC32(const unsigned char * str,unsigned int len)
{  
	unsigned int crctab[256] =
	{
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
	};
    unsigned int hash;     

    hash=0xffffffff;
    for(uint i = 0; i < len; i++){
        hash = (hash >> 8) ^ crctab[(hash & 0xFF) ^ str[i]];     
    }  
    
    hash ^= 0xFFFFFFFF;  
    return hash;     
}

unsigned int
SDBM(const unsigned char *str, unsigned int len)
{
	unsigned int hash = 0;
	
	for (uint i=0; i<len; i++) {
		hash = str[i] + (hash << 6) + (hash << 16) - hash;
	}
	
	return hash;
}

unsigned int
OCaml(const unsigned char *str, unsigned int len) 
{
	unsigned int hash = 0;

	for (uint i=0; i<len; i++) {
		hash = hash*19 + str[i];
	}

	return hash;
}

unsigned int
SML(const unsigned char *str, unsigned int len)
{
	unsigned int hash = 0;

	for (uint i=0; i<len; i++) 
	{
		hash = 33*hash + 720 + str[i];
	}

	return hash;
}

unsigned int
STL(const unsigned char *str, unsigned int len) 
{
	unsigned int hash = 0;

	for (uint i=0; i<len; i++) 
	{
		hash = 5*hash + str[i];
	}

	return hash;
}



unsigned int
FNV32(const unsigned char *str, unsigned int len)
{
    //unsigned char *bp = (unsigned char *)str;	/* start of buffer */
    //unsigned char *be = str + len;		/* beyond end of buffer */
	unsigned int hval = 0;
    for(uint i = 0; i < len; i++) {
		hval *= 0x01000193;

		//hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
		
		/* xor the bottom with the current octet */
		hval ^= (unsigned int)*str++;
    }

    /* return our new hash value */
    return hval;
}

// P. J. Weinberger Hash Function
unsigned int
PJWHash (const unsigned char *str, unsigned int len)
{
    unsigned int BitsInUnignedInt = (unsigned int) (sizeof (unsigned
							    int) * 8);
    unsigned int ThreeQuarters = (unsigned int) ((BitsInUnignedInt * 3) / 4);
    unsigned int OneEighth = (unsigned int) (BitsInUnignedInt / 8);
    unsigned int HighBits = (unsigned int) (0xFFFFFFFF) <<
	(BitsInUnignedInt - OneEighth);
    unsigned int hash = 0;
    unsigned int test = 0;
    for(uint i = 0; i < len; i++)
    {
		hash = (hash << OneEighth) + (*str++);
		if ((test = hash & HighBits) != 0)
		{
			hash = ((hash ^ (test >> ThreeQuarters)) & (~HighBits));
		}
	}
    return hash ;
}
unsigned int
MD5(const unsigned char *str, unsigned int len)
{
	MD5_CTX md5Text;
	unsigned char messageDegest[16];
	MD5Init(&md5Text);
	MD5Update(&md5Text, (unsigned char *)str, len);
	MD5Final(messageDegest, &md5Text);
	unsigned int *p = (unsigned int *)messageDegest;
	unsigned int hash = p[0];
	for(int i = 1; i < 4; i++){
		hash ^= p[i];
	}
	return hash;
}

unsigned int
SHA1(const unsigned char *str, unsigned int len)
{
	SHA1Context sha1Text;
	unsigned char messageDegest[20];
	SHA1Reset(&sha1Text);
	SHA1Input(&sha1Text, str, len);
	SHA1Result(&sha1Text, messageDegest);
	unsigned int *p = (unsigned int *)messageDegest;
	unsigned int hash = p[0];
	for(int i = 1; i < 5; i++){
		hash ^= p[i];
	}
	
	return hash;
}

unsigned int 
BOB1(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 2;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB2(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 31;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB3(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 73;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB4(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 127;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB5(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 179;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB6(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 233;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB7(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 283;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB8(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 353;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int 
BOB9(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 419;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}
unsigned int
BOB10(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 467;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((unsigned int)str[10]<<24);
		case 10: c+=((unsigned int)str[9]<<16);
		case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b+=((unsigned int)str[7]<<24);
		case 7 : b+=((unsigned int)str[6]<<16);
		case 6 : b+=((unsigned int)str[5]<<8);
		case 5 : b+=str[4];
		case 4 : a+=((unsigned int)str[3]<<24);
		case 3 : a+=((unsigned int)str[2]<<16);
		case 2 : a+=((unsigned int)str[1]<<8);
		case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB11(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 563;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB12(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 751;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB13(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 829;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB14(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 941;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB15(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 1009;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

unsigned int
	BOB16(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	unsigned int a,b,c;
	unsigned int initval = 1129;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

uint64 BOB64(const unsigned char * str, unsigned int len)
{
	//register ub4 a,b,c,len;
	uint64 a,b,c;
	uint64 initval = 1129;
	/* Set up the internal state */
	//len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a += (str[0] +((unsigned int)str[1]<<8) +((unsigned int)str[2]<<16) +((unsigned int)str[3]<<24));
		b += (str[4] +((unsigned int)str[5]<<8) +((unsigned int)str[6]<<16) +((unsigned int)str[7]<<24));
		c += (str[8] +((unsigned int)str[9]<<8) +((unsigned int)str[10]<<16)+((unsigned int)str[11]<<24));
		mix(a,b,c);
		str += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += len;
	switch(len)              /* all the case statements fall through */
	{
	case 11: c+=((unsigned int)str[10]<<24);
	case 10: c+=((unsigned int)str[9]<<16);
	case 9 : c+=((unsigned int)str[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((unsigned int)str[7]<<24);
	case 7 : b+=((unsigned int)str[6]<<16);
	case 6 : b+=((unsigned int)str[5]<<8);
	case 5 : b+=str[4];
	case 4 : a+=((unsigned int)str[3]<<24);
	case 3 : a+=((unsigned int)str[2]<<16);
	case 2 : a+=((unsigned int)str[1]<<8);
	case 1 : a+=str[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}


