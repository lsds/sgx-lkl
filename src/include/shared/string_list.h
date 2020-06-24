#ifndef _STRING_LIST_H_
#define _STRING_LIST_H_

typedef struct string_list_
{
    const char* element;
    struct string_list_* next;
} string_list_t;

string_list_t* string_list_add(string_list_t* list, const char* str);

bool string_list_contains(const string_list_t* list, const char* str);

size_t string_list_len(string_list_t* list);

void string_list_free(string_list_t* list);

#endif /* _STRING_LIST_H_ */