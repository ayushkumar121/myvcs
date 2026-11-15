#include "utils.h"

#include <sys/stat.h>

void buffer_print(FILE* f, size_t size, void* buffer) {
	for (size_t i = 0; i < size; ++i) {
		fprintf(f, "%02x", ((uint8_t*)buffer)[i]);
	}
	fprintf(f, "\n");
}

Buffer buffer_from_file(const char* file_path) {
	struct stat file_stat;
	if (stat(file_path, &file_stat) != 0) {
		fprintf(stderr, "error: file '%s' does not exist\n", file_path);
		exit(1);
	}

	FILE *f = fopen(file_path, "rb");
	if (f == NULL) {
		fprintf(stderr, "error: could not open '%s' for reading\n", file_path);
		exit(1);
	}

	size_t size = file_stat.st_size;
	char* data = malloc(size);

	if (data == NULL && size > 0) {
		fclose(f);
		fprintf(stderr, "error: out of memory\n");
		exit(1);
	}

	size_t n = size > 0 ? fread(data, 1, size, f) : 0;
	if (n != size) {
		fclose(f);
		free(data);
		fprintf(stderr, "error: could not read entire file\n");
		exit(1);
	}

	fclose(f);

	return (Buffer) {
		size, data
	};
}

const char* args_next(Args* args) {
	if (args->i < args->argc) {
		return args->argv[args->i++];
	}
	return NULL;
}

bool file_exists(const char* path) {
	struct stat file_stat;
	return stat(path, &file_stat) == 0;
}

bool folder_exists(const char* path) {
	struct stat file_stat;
	return stat(path, &file_stat) == 0 && S_ISDIR(file_stat.st_mode);
}