#ifndef _MD_HASH_TABLE_H_
#define _MD_HASH_TABLE_H_

#include <stdint.h>
#include <stddef.h>
#include "mdlinkedlist.h"

#define MD_HASH_TABLE_INITIAL_SIZE 32
#define MD_HASH_TABLE_LOAD_FACTOR 0.75f

typedef struct {
    char* key;
    uint32_t hash;
    void* value;
} md_hash_table_entry;

typedef struct {
    size_t bucket_count;
    size_t item_count;
    md_linked_list_el** buckets;
} md_hash_table;

uint32_t md_fnv1a_hash_32(const char* str);
uint64_t md_fnv1a_hash_64(const char* str);

md_hash_table* md_hash_table_init(size_t initial_size);
void md_hash_table_free(md_hash_table* table, void (*free_value)(void*));

int md_hash_table_insert(md_hash_table* table, const char* key, void* value);
void* md_hash_table_get(md_hash_table* table, const char* key);
int md_hash_table_remove(md_hash_table* table, const char* key, void (*free_value)(void*));

size_t md_hash_table_count(const md_hash_table* table);
void md_hash_table_rehash_if_needed(md_hash_table* table);

#endif
