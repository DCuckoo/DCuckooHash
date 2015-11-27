# DCuckooHash

### Introduction

Hash tables have been widely used in distributed systems, owing to their very low lookup speed. However, hash tables have two shortcomings: collisions and large memory usage. Minimal Perfect Hashing Tables (MPHT) use n buckets to store n items without collisions and redundancy. However, MPHTs come with an inability to handle fast incremental updates. DCuckoo can achieve fast lookups, fast and bounded incremental updates, with  little redundancy.

### Example

There is a little example in `main.c`, which shows the basic usage of DCuckooHash. The project is based on CMake. Run `$ cmake; make` to build.

### Other Implementations

In the directory `other` are the source code of our implementation of other six hash algorithms. There are some data files in this directory:
- `rrc00.20140608.txt.del`: The key-value pair list to initialize the hash table.
- `rrc00.20140608.txt.del.10tr`: An array of key generated from the previous file, used to search the table.
