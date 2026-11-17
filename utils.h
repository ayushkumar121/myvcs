#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#define COUNT_OF(arr) (sizeof(arr)/sizeof(arr[0]))

#define ARRAY_INIT_CAP 2
#define ARRAY(T)                                                               \
  struct {                                                                     \
    size_t length;                                                             \
    size_t capacity;                                                           \
    T *items;                                                                  \
  }

#define array_append(array, item)                                              \
  do {                                                                         \
    if ((array)->capacity < (array)->length + 1) {                             \
      (array)->capacity =                                                      \
          ((array)->capacity == 0) ? ARRAY_INIT_CAP : (array)->capacity * 1.5; \
      void* ptr = realloc(                                                     \
          (array)->items, (array)->capacity * sizeof(*(array)->items));        \
      assert(ptr != NULL);                                                     \
      (array)->items = ptr;                                                    \
    }                                                                          \
    (array)->items[(array)->length++] = (item);                                \
  } while (0)

#define array_appends(array, items, item_count)                               \
  do {                                                                        \
   for (int _i = 0; _i<(item_count); _i++) array_append((array), (items)[_i]);    \
  } while (0)

#define array_reset(array) \
    do { \
        (array)->length = 0; \
        (array)->capacity = 0; \
        (array)->items = NULL; \
   } while (0)
#define array_free(array) free((array)->items)

typedef struct {
	size_t size;
	void* data;
} Buffer;

void buffer_print(FILE* f, size_t size, void* buffer);
Buffer buffer_from_file(const char* file_path);

typedef struct {
	int i;
	int argc;
	char** argv;
} Args;

const char* args_next(Args* args);

bool file_exists(const char* path);
bool folder_exists(const char* path);

char* normalise_path(const char* path);

#endif