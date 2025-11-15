#include <stdlib.h>
#include "mdlinkedlist.h"

md_linked_list_el* md_linked_list_add(md_linked_list_el* exist_el, void* data)
{
    md_linked_list_el* new_el = calloc(1, sizeof(md_linked_list_el));
    new_el->prev = NULL;
    new_el->next = NULL;
    new_el->data = data;
    
    if (exist_el)
    {
        md_linked_list_el* last_el = exist_el;
        while(last_el->next) last_el = last_el->next;
        
        last_el->next = new_el;
        new_el->prev = last_el;
        return exist_el;
    }

    return new_el;
}


md_linked_list_el* md_linked_list_remove(md_linked_list_el* start_el, md_linked_list_el* remove_el, void (*data_free_fn)(void* data))
{
    if (!start_el)
        return NULL;
    if (!remove_el)
        return start_el;
        
    md_linked_list_el* new_start_el = start_el;
    if (start_el == remove_el)
        new_start_el = start_el->next;
        
    md_linked_list_el* prev_el = remove_el->prev;
    md_linked_list_el* next_el = remove_el->next;
    
    if (data_free_fn && remove_el->data)
        data_free_fn(remove_el->data);
    free(remove_el);
    
    if (prev_el)
        prev_el->next = next_el;
    if (next_el)
        next_el->prev = prev_el;
        
     return new_start_el;   
}

size_t md_linked_list_count(md_linked_list_el* first_el)
{
    if (!first_el)
        return 0;
        
    size_t count = 0;
    md_linked_list_el* next_el = first_el;
    
    while(next_el)
    {
        count++;
        next_el = next_el->next;
    }
    return count;
}

void md_linked_list_free_all(md_linked_list_el* first_el, void (*data_free_fn)(void* data))
{
    md_linked_list_el* el = first_el;
    while (el) {
        md_linked_list_el* next = el->next;

        if (data_free_fn && el->data)
            data_free_fn(el->data);

        free(el);
        el = next;
    }
}