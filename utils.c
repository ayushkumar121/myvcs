#include "utils.h"

#include <stdlib.h>
#include <string.h>
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

// Purely textual path normalisation
char* normalise_path(const char* path) {
	// Handling empty paths
	size_t n = strlen(path);
	if (n == 0) {
		return strdup(".");
	}

	typedef struct {
		size_t length;
		const char* name;
	} crumb;

	size_t crumbs_count = 0;
	crumb* crumbs = malloc( ((n+1)/2) * sizeof(crumb));
	if (crumbs == NULL) {
		fprintf(stderr, "error: out of memory\n");
		return NULL;
	}

	const bool leading_slash = path[0] == '/';
	const bool trailing_slash = n > 1 && path[n-1] == '/';

	size_t segment_length = 0;
	const char* segment = path;

	for (size_t i=0; i<= n; i++) {
		if (i < n && path[i] != '/') {
			segment_length++;
			continue;
		}

		if (segment_length == 0 || (segment_length == 1 && segment[0] == '.')) {
			// Do nothing
		} else if (segment_length == 2 && segment[0] == '.' && segment[1] == '.') {

			// Cannot go above the starting point
			if (crumbs_count == 0) {
				fprintf(stderr, "error: invalid path '%s' cannot go above the starting point\n", path);
				free(crumbs);
				return NULL;
			}

			crumbs_count--;
		} else {
			crumbs[crumbs_count++] = (crumb) {
				segment_length, segment
			};
		}
		segment += segment_length+1;
		segment_length = 0;
	}

	if (crumbs_count == 0) {
		free(crumbs);
		return strdup(leading_slash ? "/" : ".");
	}

	// allocating path string
	size_t cap = leading_slash + (crumbs_count - 1) + trailing_slash + 1;  // slashes + NUL
	for (size_t i = 0; i < crumbs_count; i++) cap += crumbs[i].length;

	char* normalised = malloc(cap);
	if (normalised == NULL) {
		fprintf(stderr, "error: out of memory\n");
		free(crumbs);
		return NULL;
	}

	size_t offset = 0;
	if (leading_slash) normalised[offset++] = '/';

	for (size_t i=0; i<crumbs_count; i++) {
		crumb c = crumbs[i];
		memcpy(normalised + offset, c.name, c.length);
		offset += c.length;

		if (i + 1 < crumbs_count) normalised[offset++] = '/';
	}

	if (trailing_slash) normalised[offset++] = '/';
	normalised[offset] = '\0';

	free(crumbs);
	return normalised;
}
