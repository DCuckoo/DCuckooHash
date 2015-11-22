#include <stdint.h>
#include <sys/types.h>

#ifndef HASH_DCUCKOOHASH_V4_H
#define HASH_DCUCKOOHASH_V4_H

#define MAX_KEY_SIZE 23
#define MAX_NORMAL_GROUP_NUM 30
#define USE_BLOOM_FILTER 1

#ifdef RUN_EXP
int ALLOW_KICK;
int MAX_KICK_COUNT;
int FINGERPRINT_SIZE;
#else
#define ALLOW_KICK 1
#define MAX_KICK_COUNT 0
#define FINGERPRINT_SIZE 23 // fingerprint size / bit
#endif

struct HashEntry {
    char key[MAX_KEY_SIZE];
    uint32_t val;
};

struct HashEntryP {
    char key[MAX_KEY_SIZE];
    uint32_t val;
    struct HashEntryP * next;
};

struct DCuckooHash {

    uint32_t normal_table_num;

    // normal table
    struct HashEntry * sub_tables[MAX_NORMAL_GROUP_NUM];
    uint32_t normal_table_size;
    unsigned int * fingerprint_list[MAX_NORMAL_GROUP_NUM];

    // last table
    struct HashEntryP * last_table;
    uint32_t last_table_size;
    unsigned int * last_fingerprint;
    char * last_bitmap;

    // stat

    // kick relative
    int total_blind_kick;   // total kick count from hash table building
    int kick_trigger_cnt;   // how many insertions need kick
    int max_blind_kick;     // max count of blind kick in one insertion
    int max_blind_kick_cnt; // how many kicks reach max

    // load factor relative
    int full_buckets_num[MAX_NORMAL_GROUP_NUM];
    int tot_full_buckets_num;
    int * last_table_list_length_array;
    unsigned last_table_list_items_cnt;

    int insert_memory_access_count;
    int search_memory_access_count;
    int search_mem_acc_num_count[20];
    int search_count; // total search
};

int init(uint32_t group_num, uint32_t group_size);
void reset(void);
void destroy(void);

int build_table_from_file(const char * file_name);
uint32_t find(const char * key, const uint32_t key_len);
int insert(const char * key, const uint32_t key_len, const uint32_t ins_val);
void delete(const char * key, const uint32_t key_len);

void print_stats(void);

#endif //HASH_DCUCKOOHASH_V4_H
