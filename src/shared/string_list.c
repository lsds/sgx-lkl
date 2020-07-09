#include <enclave/oe_compat.h>

#include <stdlib.h>
#include <string.h>

#include "shared/string_list.h"

string_list_t* string_list_add(string_list_t* list, const char* str)
{
    string_list_t* ns = malloc(sizeof(string_list_t));
    if (!ns)
        return list;
    ns->element = str; // no strcpy.
    ns->next = list;
    return ns;
}

int string_list_contains(const string_list_t* list, const char* str)
{
    while (list)
    {
        if (list->element == str || strcmp(list->element, str) == 0)
            return 1;
        list = list->next;
    }
    return 0;
}

size_t string_list_len(string_list_t* list)
{
    size_t r = 0;
    string_list_t* t = list;
    while (t != NULL)
    {
        r++;
        t = t->next;
    }
    return r;
}

void string_list_free(string_list_t* list)
{
    while (list)
    {
        string_list_t* n = list->next;
        // no freeing of list->element.
        free(list);
        list = n;
    }
}