#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mdhashtable.h"

#ifdef _WIN32
#define strdup _strdup /* Windows-safe strdup, or use strdup on POSIX */
#endif

// ------------------------------------------------------
// FNV-1a hash functions
// ------------------------------------------------------
uint32_t md_fnv1a_hash_32(const char* str)
{
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 16777619u;
    }
    return hash;
}

uint64_t md_fnv1a_hash_64(const char* str)
{
    uint64_t hash = 1469598103934665603ULL;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ------------------------------------------------------
// Internal helper: create an entry
// ------------------------------------------------------
static md_hash_table_entry* entry_create(const char* key, uint32_t hash, void* value)
{
    md_hash_table_entry* e = (md_hash_table_entry*)calloc(1, sizeof(md_hash_table_entry));
    if (!e)
        return NULL;

    e->key = strdup(key);
    if (!e->key) {
        free(e);
        return NULL;
    }

    e->hash = hash;
    e->value = value;
    return e;
}

// Helper to free a single entry
static void entry_free(void* data, void (*free_value)(void*))
{
    md_hash_table_entry* e = (md_hash_table_entry*)data;
    if (!e)
        return;

    free(e->key);
    if (free_value)
        free_value(e->value);
    free(e);
}

// ------------------------------------------------------
// Initialization / cleanup
// ------------------------------------------------------
void md_hash_table_free(md_hash_table* table, void (*free_value)(void*))
{
    size_t i;
    if (!table)
        return;

    for (i = 0; i < table->bucket_count; i++) {
        md_linked_list_el* el = table->buckets[i];
        while (el) {
            md_linked_list_el* next = el->next;

            /* data is md_hash_table_entry* (your internal struct) */
            md_hash_table_entry* entry = (md_hash_table_entry*)el->data;
            if (entry) {
                if (free_value && entry->value)
                    free_value(entry->value);
                if (entry->key)
                    free(entry->key);
                free(entry);
            }

            free(el);
            el = next;
        }
    }

    free(table->buckets);
    free(table);
}

// ------------------------------------------------------
// Get bucket index
// ------------------------------------------------------
static size_t bucket_index(md_hash_table* table, uint32_t hash)
{
    return hash % table->bucket_count;
}

// ------------------------------------------------------
// Insert or update
// ------------------------------------------------------
int md_hash_table_insert(md_hash_table* table, const char* key, void* value)
{
    uint32_t hash;
    size_t index;
    md_linked_list_el* el;
    md_hash_table_entry* e;
    md_hash_table_entry* new_entry;

    assert(table);
    assert(key);

    hash = md_fnv1a_hash_32(key);
    index = bucket_index(table, hash);

    el = table->buckets[index];
    while (el) {
        e = (md_hash_table_entry*)el->data;
        if (e->hash == hash && strcmp(e->key, key) == 0) {
            e->value = value;
            return 1; // updated
        }
        el = el->next;
    }

    new_entry = entry_create(key, hash, value);
    if (!new_entry)
        return 0;

    table->buckets[index] = md_linked_list_add(table->buckets[index], new_entry);
    table->item_count++;

    md_hash_table_rehash_if_needed(table);
    return 1; // inserted
}

// ------------------------------------------------------
// Lookup
// ------------------------------------------------------
void* md_hash_table_get(md_hash_table* table, const char* key)
{
    uint32_t hash;
    size_t index;
    md_linked_list_el* el;
    md_hash_table_entry* e;

    assert(table);
    assert(key);

    hash = md_fnv1a_hash_32(key);
    index = bucket_index(table, hash);

    el = table->buckets[index];
    while (el) {
        e = (md_hash_table_entry*)el->data;
        if (e->hash == hash && strcmp(e->key, key) == 0)
            return e->value;
        el = el->next;
    }
    return NULL;
}

// ------------------------------------------------------
// Remove
// ------------------------------------------------------
int md_hash_table_remove(md_hash_table* table, const char* key, void (*free_value)(void*))
{
    uint32_t hash;
    size_t index;
    md_linked_list_el* el;
    md_hash_table_entry* entry;

    if (!table || !key)
        return 0;

    hash = md_fnv1a_hash_32(key);
    index = hash % table->bucket_count;

    el = table->buckets[index];
    while (el) {
        if ((entry = (md_hash_table_entry*)el->data) != NULL &&
            entry->hash == hash && strcmp(entry->key, key) == 0)
        {
            /* unlink node from bucket list */
            if (el->prev) el->prev->next = el->next;
            else          table->buckets[index] = el->next; /* was head */

            if (el->next) el->next->prev = el->prev;

            /* free payload (value via user callback if provided) */
            if (free_value && entry->value)
                free_value(entry->value);
            if (entry->key)
                free(entry->key);
            free(entry);

            /* free the list node itself */
            free(el);

            table->item_count--;
            return 1; /* removed */
        }
        el = el->next;
    }

    return 0; /* not found */
}

// ------------------------------------------------------
// Count
// ------------------------------------------------------
size_t md_hash_table_count(const md_hash_table* table)
{
    return table ? table->item_count : 0;
}

// ------------------------------------------------------
// Auto rehash
// ------------------------------------------------------
void md_hash_table_rehash_if_needed(md_hash_table* table)
{
    float load;
    size_t new_size, i;
    md_linked_list_el** new_buckets;
    md_linked_list_el* el;
    md_linked_list_el* next;
    md_hash_table_entry* e;
    size_t new_index;

    assert(table);

    load = (float)table->item_count / (float)table->bucket_count;
    if (load < MD_HASH_TABLE_LOAD_FACTOR)
        return;

    new_size = table->bucket_count * 2;
    new_buckets = (md_linked_list_el**)calloc(new_size, sizeof(md_linked_list_el*));
    if (!new_buckets)
        return;

    for (i = 0; i < table->bucket_count; ++i) {
        el = table->buckets[i];
        while (el) {
            next = el->next;
            e = (md_hash_table_entry*)el->data;
            new_index = e->hash % new_size;

            el->prev = NULL;
            el->next = new_buckets[new_index];
            if (new_buckets[new_index])
                new_buckets[new_index]->prev = el;
            new_buckets[new_index] = el;

            el = next;
        }
    }

    free(table->buckets);
    table->buckets = new_buckets;
    table->bucket_count = new_size;
}
