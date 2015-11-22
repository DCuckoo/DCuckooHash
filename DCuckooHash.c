#include "DCuckooHash.h"
#include "lib/hash_function.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#define HASH_NUM_MAX 16


#ifdef DEBUG
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...)
#endif

uint (* hash_func[HASH_NUM_MAX])(const unsigned char * str, uint len) = {
        OCaml, RSHash, SDBM, Simple, BKDR, DEKHash, DJBHash,
        FNV32, Hsieh, PJWHash, BOB1, JSHash, OAAT, SML, APHash, STL,
};

#define FINGERPRINT_FUNC hash_func[3]

struct DCuckooHash ht;


/**
 * Declaration of functions use in this file
 */
static int add_a_group(void);
static int remove_a_group(void);
static int rebuild_last_table(void);
static int is_table_full(void);
static int is_table_sparse(void);


int init(uint32_t z, uint32_t group_size)
{
    group_size |= 1;

    if (z > MAX_NORMAL_GROUP_NUM + 1) {
        printf("ERR: Group number exceeded.\n");
        return -1;
    }

    // initialize normal table
    // array index 0 is not used, it means the last table
    ht.normal_table_num = z - 1;
    ht.normal_table_size = group_size;
    for (int i = 1; i <= ht.normal_table_num; ++i) {
        ht.sub_tables[i] = (struct HashEntry *)malloc(group_size * sizeof(struct HashEntry));
    }
    for (int i = 1; i <= ht.normal_table_num; ++i) {
        ht.fingerprint_list[i] = (unsigned int *)malloc(ht.normal_table_size * sizeof(int));
    }

    // initialize last table
    ht.last_table_size = (group_size >> 1);
    ht.last_table = (struct HashEntryP *)malloc(ht.last_table_size * sizeof(struct HashEntryP));
    ht.last_fingerprint = (unsigned int *)malloc(ht.last_table_size * sizeof(int));
    ht.last_bitmap = (char *)malloc((ht.last_table_size + 7) >> 3);

    // initialize data struct about stat
    ht.last_table_list_length_array = (int *)malloc(ht.last_table_size * sizeof(int));

    reset();

    return 0;
}

void destroy()
{
    for (int i = 1; i <= ht.normal_table_num; ++i) {
        free(ht.sub_tables[i]);
        free(ht.fingerprint_list[i]);
    }
    free(ht.last_table);
    free(ht.last_fingerprint);
    free(ht.last_bitmap);
    free(ht.last_table_list_length_array);

    return;
}

void reset()
{
    for (int i = 1; i <= ht.normal_table_num; ++i) {
        memset(ht.sub_tables[i], 0, ht.normal_table_size * sizeof(struct HashEntry));
        memset(ht.fingerprint_list[i], 0, ht.normal_table_size * sizeof(int));
    }

    memset(ht.last_table, 0, ht.last_table_size * sizeof(struct HashEntryP));
    memset(ht.last_fingerprint, 0, ht.last_table_size * sizeof(int));
    memset(ht.last_bitmap, 0, (ht.last_table_size + 7) >> 3);

    ht.total_blind_kick = 0;
    ht.kick_trigger_cnt = 0;
    ht.max_blind_kick = 0;
    ht.max_blind_kick_cnt = 0;

    memset(ht.full_buckets_num, 0, sizeof(ht.full_buckets_num));
    ht.tot_full_buckets_num = 0;
    memset(ht.last_table_list_length_array, 0, ht.last_table_size * sizeof(int));
    ht.last_table_list_items_cnt = 0;

    ht.search_memory_access_count = 0;
    ht.insert_memory_access_count = 0;
    ht.search_count = 0;
    memset(ht.search_mem_acc_num_count, 0, sizeof(ht.search_mem_acc_num_count));

    #if defined(DEBUG) || defined(RUN_EXP)
        srand(1);
    #else
        srand((unsigned)time(0));
    #endif
}


static inline uint calc_fingerprint(const char * key, uint32_t key_len)
{
    unsigned mask = (1u << FINGERPRINT_SIZE) - 1;
    return (FINGERPRINT_FUNC((const unsigned char *) key, key_len) % mask) + 1;
}

static inline void set_last_table_fingerprint(uint pos, const char * key, uint key_len)
{
    ht.last_fingerprint[pos] = calc_fingerprint(key, key_len);
}

static inline void set_normal_table_fingerprint(uint32_t group_index, uint32_t pos, const char * key, uint key_len)
{
    ht.fingerprint_list[group_index][pos] = calc_fingerprint(key, key_len);
}


static inline void set_fingerprint(uint32_t group_index, uint32_t pos, const char * key, uint key_len)
{
    if (group_index == 0) {
        set_last_table_fingerprint(pos, key, key_len);
    } else {
        set_normal_table_fingerprint(group_index, pos, key, key_len);
    }
}

static inline uint get_last_table_fingerprint(uint32_t pos)
{
    return (uint32_t)ht.last_fingerprint[pos] & ((1 << FINGERPRINT_SIZE) - 1);
}

static inline uint get_normal_table_fingerprint(uint group_index, uint pos)
{
    return (uint32_t)ht.fingerprint_list[group_index][pos] & ((1 << FINGERPRINT_SIZE) - 1);
}


// only for 8-bit per fp
static inline uint32_t get_fingerprint(uint32_t group_index, uint32_t pos)
{
    if (group_index == 0) {
        return get_last_table_fingerprint(pos);
    } else {
        return get_normal_table_fingerprint(group_index, pos);
    }
}

static inline void clear_fingerprint(uint group_index, uint pos)
{
    if (group_index == 0) {
        ht.last_fingerprint[pos] = 0;
    } else {
        ht.fingerprint_list[group_index][pos] = 0;
    }
}

static inline uint32_t get_element_pos_in_normal_group(uint32_t group_index, const char * key, const uint32_t key_len)
{
    return hash_func[group_index % HASH_NUM_MAX]((const unsigned char *) key, key_len) % ht.normal_table_size;
}

static inline uint32_t get_element_pos_in_last_group(const char * key, const uint32_t key_len)
{
    return hash_func[0]((const unsigned char *)key, key_len) % ht.last_table_size;
}

static inline uint32_t get_element_pos_in_group(uint32_t group_index, const char * key, const uint32_t key_len)
{
    if (group_index == 0)
        return get_element_pos_in_last_group(key, key_len);
    else
        return get_element_pos_in_normal_group(group_index, key, key_len);
}


static inline void set_revert_flag(const char * key, const uint32_t key_len)
{
    if (!USE_BLOOM_FILTER)
        return;
    uint pos;
    pos = get_element_pos_in_last_group(key, key_len);
    ht.last_fingerprint[pos] |= (1 << 31);
    for (uint i = 1; i <= ht.normal_table_num; ++i) {
        pos = get_element_pos_in_normal_group(i, key, key_len);
        ht.fingerprint_list[i][pos] |= (1 << 31);
    }
}

static inline int get_revert_flag(const char * key, const uint32_t key_len)
{
    if (!USE_BLOOM_FILTER)
        return 0;
    int result = 1;
    uint pos;
    pos = get_element_pos_in_last_group(key, key_len);
    result &= (ht.last_fingerprint[pos] >> 31);
    for (uint i = 1; i <= ht.normal_table_num; ++i) {
        pos = get_element_pos_in_normal_group(i, key, key_len);
        result &= ht.fingerprint_list[i][pos] >> 31;
    }
    return result;
}


static inline void insert_into_normal_table(uint32_t group_index, uint32_t pos, const char *key, const uint32_t key_len,
                                            uint32_t val)
{
    strcpy(ht.sub_tables[group_index][pos].key, key);
    ht.sub_tables[group_index][pos].val = val;
    set_fingerprint(group_index, pos, key, key_len);
}

static inline void insert_into_last_table(uint32_t pos, const char *key, const uint32_t key_len, uint32_t val)
{
    strcpy(ht.last_table[pos].key, key);
    ht.last_table[pos].val = val;
    set_fingerprint(0, pos, key, key_len);
}

static inline void insert_into_table(uint32_t group_index, uint32_t pos, const char *key, const uint32_t key_len,
                              uint32_t val)
{
    if (group_index == 0) {
        insert_into_last_table(pos, key, key_len, val);
    } else {
        insert_into_normal_table(group_index, pos, key, key_len, val);
    }
}

#define get_normal_table_key(group_index, pos) ht.sub_tables[group_index][pos].key
#define get_last_table_key(pos) ht.last_table[pos].key
static inline char * get_table_key(uint32_t group_index, uint32_t pos)
{
    if (group_index == 0) {
        return get_last_table_key(pos);
    } else {
        return get_normal_table_key(group_index, pos);
    }
}

#define get_normal_table_val(group_index, pos) ht.sub_tables[group_index][pos].val
#define get_last_table_val(pos) ht.last_table[pos].val
static inline uint get_table_val(uint32_t group_index, uint32_t pos)
{
    if (group_index == 0) {
        return get_last_table_val(pos);
    } else {
        return get_normal_table_val(group_index, pos);
    }
}


static inline void set_last_bitmap(uint pos)
{
    ht.last_bitmap[pos / 8] |= (1 << (pos & 7));
}

static inline void reset_last_bitmap(uint pos)
{
    ht.last_bitmap[pos / 8] &= ~(1 << (pos & 7));
}

static inline int get_last_bitmap(uint pos)
{
    return (ht.last_bitmap[pos / 8] & (1 << (pos & 7))) != 0;
}


int build_table_from_file(const char * file_name)
{
    FILE *fp;
    char str[MAX_KEY_SIZE];
    int val, cnt = 0;

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("File not found.\n");
        return -1;
    }
    while (fscanf(fp, "%s %d", str, &val) == 2) {
        insert(str, (uint)strlen(str), (uint)val);
        ++cnt;
    }
    fclose(fp);

    return cnt;
}


static inline void stat_blind_kick(int cnt)
{
    ht.total_blind_kick += cnt;
    ht.kick_trigger_cnt++;
    if (cnt > ht.max_blind_kick) {
        ht.max_blind_kick = cnt;
        ht.max_blind_kick_cnt = 1;
    } else if (cnt == ht.max_blind_kick) {
        ht.max_blind_kick_cnt++;
    }
}


static int insert_float_element(const char * key, uint32_t key_len, uint ins_val)
{
    int k;
    char float_key[2][MAX_KEY_SIZE];
    uint float_val[2];
    uint float_key_len[2];

    strcpy(float_key[0], key);
    float_val[0] = ins_val;
    float_key_len[0] = key_len;

    for (k = 0; ALLOW_KICK && k <= MAX_KICK_COUNT; ++k) {

        dbg_printf("\t inserting float key: %s\n", float_key[k % 2]);

        // find a bucket which has another candidate
        for (int i = ht.normal_table_num; i >= 0; --i) {
            uint i_pos = get_element_pos_in_group((uint)i, float_key[k % 2], float_key_len[k % 2]);
            int j;
            uint j_pos;

            strcpy(float_key[(k + 1) % 2], get_table_key((uint)i, i_pos));
            float_val[(k + 1) % 2] = get_table_val((uint)i, i_pos);
            float_key_len[(k + 1) % 2] = (uint)strlen(float_key[(k + 1) % 2]);

            ++ht.insert_memory_access_count;

            for (j = ht.normal_table_num; j >= 0; --j) {
                j_pos = get_element_pos_in_group((uint)j, float_key[(k + 1) % 2], float_key_len[(k + 1) % 2]);
                if (get_fingerprint((uint)j, j_pos) == 0) {
                    // find one, insert
                    dbg_printf("\t Candidate found.\n");
                    stat_blind_kick(k + 1);

                    ++ht.full_buckets_num[j]; // stat
                    ++ht.tot_full_buckets_num;

                    ht.insert_memory_access_count += 2;

                    insert_into_table((uint)i, i_pos, float_key[k % 2], float_key_len[k % 2], float_val[k % 2]);
                    insert_into_table((uint)j, j_pos, float_key[(k + 1) % 2], float_key_len[(k + 1) % 2], float_val[(k + 1) % 2]);
                    return 0;
                }
            }
        }

        if (k == MAX_KICK_COUNT) {
            break;
        }

        // not found, kick one randomly
        uint group_index = rand() % (ht.normal_table_num + 1);
        uint pos = get_element_pos_in_group(group_index, float_key[k % 2], float_key_len[k % 2]);

        ht.insert_memory_access_count += 2;

        strcpy(float_key[(k + 1) % 2], get_table_key(group_index, pos));
        float_val[(k + 1) % 2] = get_table_val(group_index, pos);
        float_key_len[(k + 1) % 2] = (uint)strlen(float_key[(k + 1) % 2]);

        insert_into_table(group_index, pos, float_key[k % 2], float_key_len[k % 2], float_val[k % 2]);
    }

    // kick not finished in MAX_KICK_COUNT
    // append it to the last list
    dbg_printf("\t Kick too many times. Insert to list: %s\n", float_key[k % 2]);
    stat_blind_kick(k);
    uint pos = get_element_pos_in_last_group(float_key[k % 2], float_key_len[k % 2]);
    struct HashEntryP * p, * next_pointer;
    p = &ht.last_table[pos];
    next_pointer = p->next;
    p->next = malloc(sizeof(struct HashEntryP));
    if (p->next == NULL) {
        printf("Error: could not malloc more space.\n");
        return -1;
    }
    p = p->next;
    strcpy(p->key, float_key[k % 2]);
    p->val = float_val[k % 2];
    p->next = next_pointer;
    set_last_bitmap(pos);
    ht.insert_memory_access_count += 2;

    ++ht.last_table_list_length_array[pos]; // stat
    ++ht.last_table_list_items_cnt;

    return 0;
}

int insert(const char *key, const uint32_t key_len, const uint32_t ins_val)
{
    dbg_printf("insert: %s %d\n", key, ins_val);
    // find empty bucket
    for (int i = ht.normal_table_num; i >= 0; --i) {
        uint pos = get_element_pos_in_group((uint)i, key, key_len);
        if (get_fingerprint((uint)i, pos) == 0) {
            insert_into_table((uint)i, pos, key, key_len, ins_val);
            ++ht.full_buckets_num[i];
            ++ht.tot_full_buckets_num;
            ++ht.insert_memory_access_count;
            dbg_printf("\t directly: group %d; bucket %d\n", i, pos);
            return 0;
        }
    }

    if (insert_float_element(key, key_len, ins_val) != 0) {
        printf("Insert failed\n");
        return -1;
    }

    if (is_table_full()) {
        add_a_group();
    }

    return 0;
}

uint32_t find(const char *key, const uint32_t key_len)
{
    ht.search_count++;

    uint search_fingerprint = calc_fingerprint(key, key_len);
    uint last_pos;
    int fp_collision_flag = 0;
    int mem_acc_count = 0;

    if (!get_revert_flag(key, key_len)) {

        for (int i = ht.normal_table_num; i > 0; --i) {
            uint pos = get_element_pos_in_normal_group((uint)i, key, key_len);
            if (get_normal_table_fingerprint((uint)i, pos) == search_fingerprint) {
                // fingerprint match, check off-chip table
                ++mem_acc_count;
                if (fp_collision_flag)
                    set_revert_flag(key, key_len);
                else
                    fp_collision_flag = 1;
                if (strcmp(key, get_normal_table_key((uint)i, pos)) == 0) {
                    ht.search_memory_access_count += mem_acc_count;
                    ++ht.search_mem_acc_num_count[mem_acc_count];
                    return get_normal_table_val((uint)i, pos);
                }
            }
        }

        // search last table
        last_pos = get_element_pos_in_last_group(key, key_len);
        if (get_last_table_fingerprint(last_pos) == search_fingerprint) {
            // fingerprint match, check off-chip table
            ++mem_acc_count;
            if (strcmp(key, get_last_table_key(last_pos)) == 0) {
                ht.search_memory_access_count += mem_acc_count;
                ++ht.search_mem_acc_num_count[mem_acc_count];
                return get_last_table_val(last_pos);
            }
        }
    } else {
        // search last table
        last_pos = get_element_pos_in_last_group(key, key_len);
        if (get_last_table_fingerprint(last_pos) == search_fingerprint) {
            // fingerprint match, check off-chip table
            ++mem_acc_count;
            if (strcmp(key, get_last_table_key(last_pos)) == 0) {
                ht.search_memory_access_count += mem_acc_count;
                ++ht.search_mem_acc_num_count[mem_acc_count];
                return get_last_table_val(last_pos);
            }
        }

        for (int i = 1; i <= ht.normal_table_num; ++i) {
            uint pos = get_element_pos_in_normal_group((uint)i, key, key_len);
            if (get_normal_table_fingerprint((uint)i, pos) == search_fingerprint) {
                // fingerprint match, check off-chip table
                ++mem_acc_count;
                if (strcmp(key, get_normal_table_key((uint)i, pos)) == 0) {
                    ht.search_memory_access_count += mem_acc_count;
                    ++ht.search_mem_acc_num_count[mem_acc_count];
                    return get_normal_table_val((uint)i, pos);
                }
            }
        }
    }

    if (get_last_bitmap(last_pos)) {
        // if has linked list
        struct HashEntryP * p;
        ++mem_acc_count;
        p = ht.last_table[last_pos].next;
        while (p) {
            ++mem_acc_count;
            if (strcmp(key, p->key) == 0) {
                ht.search_memory_access_count += mem_acc_count;
                ++ht.search_mem_acc_num_count[mem_acc_count];
                return p->val;
            }
            p = p->next;
        }
    }

    return 0;
}


void delete(const char *key, const uint32_t key_len)
{
    for (int i = ht.normal_table_num; i > 0; --i) {
        uint pos = get_element_pos_in_normal_group((uint)i, key, key_len);
        if (get_fingerprint((uint)i, pos) == calc_fingerprint(key, key_len)) {
            // fingerprint match, check off-chip table
            if (strcmp(key, get_table_key((uint)i, pos)) == 0) {
                clear_fingerprint((uint)i, pos);
                // No need to reset off-chip table ?
                ht.sub_tables[i][pos].val = 0;
                --ht.full_buckets_num[i];
                --ht.tot_full_buckets_num;

                return;
            }
        }
    }
    {
        // search last table
        uint pos = get_element_pos_in_last_group(key, key_len);
        if (get_fingerprint(0, pos) == calc_fingerprint(key, key_len)) {
            // fingerprint match, check off-chip table
            if (strcmp(key, get_table_key(0, pos)) == 0) {
                clear_fingerprint(0, pos);
                if (get_last_bitmap(pos)) {
                    struct HashEntryP * p;
                    p = ht.last_table[pos].next;
                    memcpy(&ht.last_table[pos], p, sizeof(*p));
                    free(p);
                    p = &ht.last_table[pos];
                    set_fingerprint(0, pos, p->key, (uint)strlen(p->key));
                    --ht.last_table_list_length_array[pos]; // stat
                    --ht.last_table_list_items_cnt;
                    if (!p->next) {
                        reset_last_bitmap(pos);
                    }
                }
                return;
            }
        }
        if (get_last_bitmap(pos)) {
            // if has linked list
            struct HashEntryP * p, * prev;
            int cnt;
            prev = &(ht.last_table[pos]);
            p = ht.last_table[pos].next;
            for (cnt = 0; p; ++cnt, prev = p, p = p->next) {
                if (strcmp(key, p->key) == 0) {
                    prev->next = p->next;
                    free(p);
                    if (cnt == 0 && prev->next == NULL)
                        reset_last_bitmap(pos);
                    --ht.last_table_list_length_array[pos]; // stat
                    --ht.last_table_list_items_cnt;
                    return;
                }
            }
        }
    }

    if (is_table_sparse()) {
        remove_a_group();
    }
}


static int add_a_group()
{
    if (ht.normal_table_num < MAX_NORMAL_GROUP_NUM) {
        int index = ++ht.normal_table_num;

        ht.full_buckets_num[index] = 0;

        ht.sub_tables[index] = (struct HashEntry *)malloc(ht.normal_table_size * sizeof(struct HashEntry));
        memset(ht.sub_tables[index], 0, ht.normal_table_size * sizeof(struct HashEntry));

        ht.fingerprint_list[index] = (unsigned int *)malloc(ht.normal_table_size * sizeof(int));
        memset(ht.fingerprint_list[index], 0, ht.normal_table_size * sizeof(int));

        rebuild_last_table();
        return 0;
    } else {
        return -1;
    }
}

static int remove_a_group()
{
    uint index = ht.normal_table_num--;

    ht.tot_full_buckets_num -= ht.full_buckets_num[index];

    for (uint i = 0; i < ht.normal_table_size; ++i) {
        const char * key = get_table_key(index, i);
        uint val = get_table_val(index, i);
        insert_float_element(key, (uint)strlen(key), val);
    }

    free(ht.sub_tables[index]);
    free(ht.fingerprint_list[index]);
    return 0;
}

static int is_table_full()
{
    // do something with ht.full_buckets_num or ht.last_table_list_length_array
    return 0;
    return (100 * ht.tot_full_buckets_num / (ht.normal_table_num * ht.normal_table_size + ht.last_table_size) >= 96);
}

static int is_table_sparse()
{
    return 0;
    return (100 * ht.tot_full_buckets_num / (ht.normal_table_num * ht.normal_table_size + ht.last_table_size) <= 50);
}

static int rebuild_last_table()
{
    for (uint i = 0; i < ht.last_table_size; ++i) {
        if (get_fingerprint(0, i)) {
            struct HashEntryP * linked_list = ht.last_table[i].next;
            ht.last_table[i].next = NULL;
            ht.last_table_list_items_cnt -= ht.last_table_list_length_array[i];
            ht.last_table_list_length_array[i] = 0;
            reset_last_bitmap(i);
            while (linked_list) {
                struct HashEntryP * now = linked_list;
                linked_list = now->next;
                insert(now->key, (uint)strlen(now->key), now->val);
                free(now);
            }
        }
    }

    return 0;
}

void print_stats()
{
    printf("Loading factor:\n");

    int tot = 0;

    for (uint i = 1; i <= ht.normal_table_num; ++i) {
        int cnt = 0;
        for (uint j = 0; j < ht.normal_table_size; ++j) {
            if (get_fingerprint(i, j)) {
                ++cnt;
            }
        }
        tot += cnt;
        printf("\tGroup #%02d: %.4lf (%d/%d)\n", i, (double)cnt / ht.normal_table_size, cnt, ht.normal_table_size);
    }
    {
        int cnt = 0;
        int total_list_len = 0, max_list_len = 0, min_list_len = 10000;

        for (uint j = 0; j < ht.last_table_size; ++j) {
            if (get_fingerprint(0, j)) {
                ++cnt;

                struct HashEntryP * p;
                int link_len = 0;
                p = ht.last_table[j].next;
                while (p) {
                    p = p->next;
                    ++link_len;
                }
                max_list_len = max_list_len > link_len ? max_list_len : link_len;
                min_list_len = min_list_len < link_len ? min_list_len : link_len;
                total_list_len += link_len;
            }
        }
        tot += cnt;
        printf("\tGroup #00: %.4lf (%d/%d)\n", (double)cnt / ht.last_table_size, cnt, ht.last_table_size);
        printf("\t\tList length: Avg %.2lf, Max %d, Min %d\n", (double)total_list_len / ht.last_table_size, max_list_len, min_list_len);
    }

    printf("\n\tTotal: %.4lf (%d/%d)\n",
           (double)tot / (ht.normal_table_num * ht.normal_table_size + ht.last_table_size),
           tot, ht.normal_table_num * ht.normal_table_size + ht.last_table_size);

    printf("\nKick count: Avg: %.2lf(Tot: %d), Max: %d, MaxNum %d\n",
           (double)ht.total_blind_kick / ht.kick_trigger_cnt, ht.kick_trigger_cnt, ht.max_blind_kick, ht.max_blind_kick_cnt);

    printf("\nSearch Mem Acc count: %d (%.5lf)\n", ht.search_memory_access_count, ht.search_memory_access_count / (double)ht.search_count);

    return;
}
