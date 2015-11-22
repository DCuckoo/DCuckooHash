#include "DCuckooHash.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_READ 500000

char input_file_name[] = "../sample.txt";

struct KVPair
{
    char ip[24];
    int val;
} input[MAX_READ];

int main()
{
    char ip[24];
    int val;
    FILE *fp;
    int i, tot, s_cnt = 0;
    clock_t start, end;

    // 1000 key-value pairs in sample.txt
    // for β=1.05, 1000 * 1.05 / 7.5 = 139 buckets per group
    init(8, 139);

    tot = build_table_from_file(input_file_name);
    printf("Insert %d element finished.\n", tot);

    fp = fopen(input_file_name, "r");
    for (i = 0; i < MAX_READ; ++i) {
        if (!fscanf(fp, "%s %d", input[i].ip, &input[i].val))
            break;
    }
    fclose(fp);

    start = clock();
    int cnt = 0;
    for (int k = 0; k < 5; ++k) {
        for (i = 0; i < MAX_READ && i < tot; ++i) {
            val = find(input[i].ip, (uint32_t)strlen(input[i].ip));
            if (val != input[i].val) {
                ++cnt;
                printf("%3d %s %5d %5d\n", i, ip, input[i].val, val);
            }
        }
        s_cnt += i;
    }
    end = clock();

    if (cnt == 0) {
        printf("Search for %d element.\n", s_cnt);
        printf("All green. (%.4lfs)\n", (double)(end - start) / CLOCKS_PER_SEC);
        print_stats();
    }

    return 0;
}
