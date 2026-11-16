#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define COUNT_OF(arr) (sizeof(arr)/sizeof(arr[0]))

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