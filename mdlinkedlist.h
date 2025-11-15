#ifndef _MD_LINKED_LIST_H
#define _MD_LINKED_LIST_H

#include <stdint.h>

typedef struct md_linked_list_el {
    void* data;
    struct md_linked_list_el* prev;
    struct md_linked_list_el* next;
} md_linked_list_el;

md_linked_list_el* md_linked_list_add(md_linked_list_el* exist_el, void* data);
md_linked_list_el* md_linked_list_remove(md_linked_list_el* start_el, md_linked_list_el* remove_el, void (*data_free_fn)(void* data));
size_t md_linked_list_count(md_linked_list_el* first_el);
void md_linked_list_free_all(md_linked_list_el* first_el, void (*data_free_fn)(void* data));
#endif