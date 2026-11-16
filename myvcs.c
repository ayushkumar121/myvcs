#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <zlib.h>
#include <arpa/inet.h>

#include "utils.h"
#include "sha1.h"

#define DATABASE_DIRECTORY ".myvcs"
#define MAIN_BRANCH_NAME   "main"
#define OBJECT_PATH_LENGTH 64

typedef struct {
	const char* type;
	size_t size;
	uint8_t* data;
} Object;

enum {
	FILE_MODE_REGULAR = 0100644,
	FILE_MODE_EXECUTABLE = 0100755,
	FILE_MODE_SYMLINK = 0120000,
	FILE_MODE_DIRECTORY = 0040000,
	FILE_MODE_SUBMODULE = 0160000
};

typedef struct {
	uint32_t ctime_s;
	uint32_t ctime_ns;
	uint32_t mtime_s;
	uint32_t mtime_ns;
	uint32_t dev;
	uint32_t ino;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t file_size;
	uint8_t hash[20];
	uint16_t flags;
	const char* path;
} IndexEntry;

typedef struct {
	uint32_t version;
	uint32_t count;
	uint32_t capacity;
	IndexEntry* entries;
	uint8_t hash[20];
} Index;

typedef struct TreeNode TreeNode;

struct TreeNode {
	size_t size;
	const char* name;
	size_t name_length;
	uint32_t mode;
	uint8_t hash[20];

	ARRAY(TreeNode*) children;

	// Serialised object
	Object object;
};

#define EMPTY_INDEX ((Index){.version = 2})

// Commands
static void myvcs_init(Args* args);
static void myvcs_hash_objects(Args* args);
static void myvcs_cat_file(Args* args);
static void myvcs_add_file(Args* args);
static void myvcs_ls_files(Args* args);
static void myvcs_write_tree(Args* args);

// Helpers
static Object myvcs_object_from_file(const char* type, const char* file_path);
static void myvcs_object_write(const char hex[41], Object object);
static bool myvcs_object_check_type(const char* type);
static Index myvcs_index_read(void);
static void myvcs_index_add(Index* index, IndexEntry entry);
static int myvcs_index_entry_compare(const void* a, const void* b);
static void myvcs_index_write(Index index);
static uint32_t mode_from_state(mode_t mode);
static TreeNode* myvcs_tree_build(Index index, size_t start, size_t end, size_t prefix_len);
static void myvcs_tree_write(TreeNode* root);
static void myvcs_tree_print(Object object, FILE* f);

// Zlib helpers
static Buffer zlib_compress(size_t size, const void* data);
static Buffer zlib_uncompress(size_t size, const void* data);

static uint8_t zeroes[64] = {0};

int main(int argc, char** argv) {
	if (argc < 2) {
		fprintf(stderr, "error: no subcommand provided\n");
		exit(1);
	}

	Args args = (Args) {
		1, argc, argv
	};

	const char* subcommand = args_next(&args);
	if (strcmp(subcommand, "init") == 0) {
		myvcs_init(&args);
	} else if (strcmp(subcommand, "hash-object") == 0) {
		myvcs_hash_objects(&args);
	} else if (strcmp(subcommand, "cat-file") == 0) {
		myvcs_cat_file(&args);
	} else if (strcmp(subcommand, "add") == 0) {
		myvcs_add_file(&args);
	} else if (strcmp(subcommand, "ls-files") == 0) {
		myvcs_ls_files(&args);
	} else if (strcmp(subcommand, "write-tree") == 0) {
		myvcs_write_tree(&args);
	} else {
		fprintf(stderr, "error: unknown subcommand %s\n", subcommand);
		exit(1);
	}

	return 0;
}

void myvcs_init(Args* args) {
	(void)args;

	if (folder_exists(DATABASE_DIRECTORY)) {
	}

	if (mkdir(DATABASE_DIRECTORY, 0777) != 0 && errno != EEXIST) {
		fprintf(stderr, "error: could not create " DATABASE_DIRECTORY "\n");
		exit(1);
	}

	mkdir(DATABASE_DIRECTORY "/objects", 0777);
	mkdir(DATABASE_DIRECTORY "/refs", 0777);
	mkdir(DATABASE_DIRECTORY "/refs/heads", 0777);

	FILE *f = fopen(DATABASE_DIRECTORY "/HEAD", "w"); // current branch
	if (f == NULL) {
		fprintf(stderr, "error: could not open " DATABASE_DIRECTORY "/HEAD\n");
		exit(1);
	}
	fprintf(f, "ref: refs/heads/" MAIN_BRANCH_NAME "\n");
	fclose(f);

	fprintf(stderr, "myvcs: repository initialised\n");
}

void myvcs_hash_objects(Args* args) {
	const char* type = "blob";
	const char* arg;

	bool write = false;

	int file_count = 0;
	const char** file_paths = malloc(args->argc * sizeof(char*));

	// Argument parsing
	while ((arg = args_next(args)) != NULL) {
		if (arg[0] == '-') {
			if (strcmp(arg, "-t") == 0) {
				type = args_next(args);
				if (type == NULL) {
					fprintf(stderr, "error: type not provided\n");
					exit(1);
				}
				if (!myvcs_object_check_type(type)) {
					fprintf(stderr, "error: unknown type '%s' expected (blob | tree | commit | tag)\n", type);
					exit(1);
				}
			} else if (strcmp(arg, "-w") == 0) {
				write = true;
			} else {
				fprintf(stderr, "error: unknown flag '%s'\n", arg);
				exit(1);
			}
			continue;
		}
		file_paths[file_count++] = arg;
	}

	for (int i = 0; i < file_count; ++i) {
		const char* file_path = file_paths[i];
		Object object = myvcs_object_from_file(type, file_path);

		uint8_t hash[20];
		sha1(object.size, object.data, hash);

		char hex[41];
		hash_to_string(hash, hex);

		if (write) {
			myvcs_object_write(hex, object);
		}

		fprintf(stdout, "%s\n", hex);

		free(object.data);
	}

	free(file_paths);
}

void myvcs_cat_file(Args* args) {
	const char* arg;
	const char* hash = NULL;
	enum {CAT_OP_NONE, CAT_OP_PRINT, CAT_OP_TYPE, CAT_OP_SIZE} cat_op = 0;

	// Argument parsing
	while ((arg = args_next(args)) != NULL) {
		if (arg[0] == '-') {
			if (cat_op != CAT_OP_NONE) {
				fprintf(stderr, "error: operation mode already defined\n");
				exit(1);
			}
			if (strcmp(arg, "-p") == 0) {
				cat_op = CAT_OP_PRINT;
			} else if (strcmp(arg, "-t") == 0) {
				cat_op = CAT_OP_TYPE;
			} else if (strcmp(arg, "-s") == 0) {
				cat_op = CAT_OP_SIZE;
			} else {
				fprintf(stderr, "error: unknown flag '%s'\n", arg);
				exit(1);
			}
			continue;
		}

		if (hash == NULL) {
			hash = arg;
		} else {
			fprintf(stderr, "error: too many arguments\n");
			exit(1);
		}
	}

	if (cat_op == CAT_OP_NONE) {
		fprintf(stderr, "error: operation mode not defined\n");
		exit(1);
	}

	if (hash == NULL) {
		fprintf(stderr, "error: hash not provided\n");
		exit(1);
	}

	if (strlen(hash) != 40) {
		fprintf(stderr, "error: hash should be exactly 40 characters\n");
		exit(1);
	}

	char path[OBJECT_PATH_LENGTH];
	snprintf(path, sizeof(path), DATABASE_DIRECTORY "/objects/%c%c/%s", hash[0], hash[1], hash+2);

	Buffer compressed = buffer_from_file(path);
	Buffer uncompressed = zlib_uncompress(compressed.size, compressed.data);

	uint8_t* header_end = memchr(uncompressed.data, '\0', uncompressed.size);
	if (header_end == NULL) {
		fprintf(stderr, "error: corrupted object\n");
		exit(1);
	}
	size_t header_size = header_end - (uint8_t *)uncompressed.data;

	char* header = uncompressed.data;
	uint8_t* content = uncompressed.data + header_size + 1;
	size_t content_len = uncompressed.size - header_size - 1;

	fprintf(stderr, "myvcs: header: %s\n", (char*)header);

	char* space = memchr(header, ' ', header_size);
	if (space == NULL) {
		fprintf(stderr, "error: corrupted header\n");
		exit(1);
	}

	size_t declared = strtoull(space + 1, NULL, 10);
	if (declared != content_len) {
		fprintf(stderr, "error: corrupt object (size mismatch)\n");
		exit(1);
	}

	size_t type_len = space - header;

	switch (cat_op) {
	case CAT_OP_TYPE:
		fwrite(header, type_len, 1, stdout);
		fputc('\n', stdout);
		break;
	case CAT_OP_SIZE:
		fprintf(stdout, "%zu\n", content_len);
		break;
	case CAT_OP_PRINT:
		if (type_len == 4 && memcmp(header, "tree", 4) == 0) { // Pretty print tree
			Object tree = {"tree", content_len, content};
			myvcs_tree_print(tree, stdout);
		} else {
			fwrite(content, 1, content_len, stdout);
		}
		break;
	case CAT_OP_NONE:
		break;
	}
}

void myvcs_add_file(Args* args) {
	const char* arg;

	int file_count = 0;
	const char** file_paths = malloc(args->argc * sizeof(char*));

	// Argument parsing
	while ((arg = args_next(args)) != NULL) {
		if (arg[0] == '-') {
			fprintf(stderr, "error: unsupported flag '%s'\n", arg);
			exit(1);
		}
		file_paths[file_count++] = arg;
	}

	if (file_count == 0) {
		fprintf(stderr, "error: no files provided\n");
		exit(1);
	}

	Index index = myvcs_index_read();

	for (int i = 0; i < file_count; i++) {
		const char* file_path = file_paths[i];

		char* normal_path = normalise_path(file_path);
		if (normal_path == NULL) {
			fprintf(stderr, "error: could not normalise path '%s'\n", file_path);
			exit(1);
		}
		fprintf(stderr, "myvcs: normalised path: %s\n", normal_path);

		size_t db_directory_len = sizeof(DATABASE_DIRECTORY)-1;
		if (strncmp(normal_path, DATABASE_DIRECTORY, db_directory_len) == 0 &&
		        (normal_path[db_directory_len] == '\0' || normal_path[db_directory_len] == '/')) {
			fprintf(stderr, "error: cannot add files from '" DATABASE_DIRECTORY "'\n");
			exit(1);
		}

		// TODO: implement recursive adding of files from folder
		if (folder_exists(normal_path)) {
			fprintf(stderr, "myvcs: adding folder is not supported\n");
			exit(1);
		}

		const Object object = myvcs_object_from_file("blob", normal_path);

		uint8_t hash[20];
		sha1(object.size, object.data, hash);

		char hex[41];
		hash_to_string(hash, hex);

		fprintf(stderr, "myvcs: adding file: %s %s\n", normal_path, hex);

		myvcs_object_write(hex, object);

		IndexEntry entry;

		struct stat file_stat;
		if (stat(normal_path, &file_stat) != 0) {
			fprintf(stderr, "error: file '%s' does not exist\n", file_path);
			exit(1);
		}

		entry.ctime_s = file_stat.st_ctimespec.tv_sec;
		entry.ctime_ns = file_stat.st_ctimespec.tv_nsec;
		entry.mtime_s = file_stat.st_mtimespec.tv_sec;
		entry.mtime_ns = file_stat.st_mtimespec.tv_nsec;

		entry.mode = mode_from_state(file_stat.st_mode);
		entry.dev = file_stat.st_dev;
		entry.ino = file_stat.st_ino;
		entry.uid = file_stat.st_uid;
		entry.gid = file_stat.st_gid;
		entry.file_size = file_stat.st_size;
		entry.flags = 0;
		memcpy(entry.hash, hash, 20);
		entry.path = normal_path; // Leak

		// Find existing index or add it
		bool found = false;
		for (uint32_t j = 0; j < index.count; j++) {
			if (strcmp(index.entries[j].path, entry.path) == 0) {
				free((void*)index.entries[j].path);
				index.entries[j] = entry;
				found = true;
				break;
			}
		}
		if (!found) myvcs_index_add(&index, entry);
	}

	myvcs_index_write(index);
}

void myvcs_ls_files(Args* args) {
	const char* arg;
	bool stage = false;

	// Argument parsing
	while ((arg = args_next(args)) != NULL) {
		if (arg[0] == '-') {
			if (strcmp(arg, "-s") == 0 || strcmp(arg, "--stage") == 0) {
				stage = true;
			} else {
				fprintf(stderr, "error: unsupported flag '%s'\n", arg);
				exit(1);
			}
		}
	}

	const Index index = myvcs_index_read();
	for (size_t i = 0; i < index.count; i++) {
		const IndexEntry* entry = &index.entries[i];
		if (stage) {
			char hex[41];
			hash_to_string(entry->hash, hex);
			printf("%o %s %u\t%s\n", entry->mode, hex, (entry->flags >> 12) & 0x3, entry->path);
		} else {
			printf("%s\n", entry->path);
		}
	}
}

void myvcs_write_tree(Args* args) {
	(void)args;

	Index index = myvcs_index_read();
	TreeNode* root = myvcs_tree_build(index, 0, index.count, 0);

	myvcs_tree_write(root);
}

// Helpers

// Rename
Object myvcs_object_from_file(const char* type, const char* file_path) {
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

	size_t content_size = file_stat.st_size;
	size_t header_size = snprintf(NULL, 0, "%s %zu", type, content_size) + 1;

	size_t object_size = header_size + content_size;
	uint8_t *object_data = malloc(object_size);
	assert(object_data != NULL);

	snprintf((char*)object_data, header_size, "%s %zu", type, content_size);
	if (fread(object_data + header_size, 1, content_size, f) != content_size) {
		fprintf(stderr, "error: could not read entire file '%s'\n", file_path);
		exit(1);
	}

	return (Object) {
		type, object_size, object_data
	};
}

void myvcs_object_write(const char hex[41], Object object) {
	if (!folder_exists(DATABASE_DIRECTORY)) {
		fprintf(stderr, "error: not a repository\n");
		exit(1);
	}

	if (!folder_exists(DATABASE_DIRECTORY "/objects")) {
		fprintf(stderr, "error: corrupted repository\n");
		exit(1);
	}

	char path[OBJECT_PATH_LENGTH];
	snprintf(path, sizeof(path), DATABASE_DIRECTORY "/objects/%c%c", hex[0], hex[1]);
	mkdir(path, 0777);

	snprintf(path, sizeof(path), DATABASE_DIRECTORY "/objects/%c%c/%s", hex[0], hex[1], hex+2);

	if (!file_exists(path)) {
		fprintf(stderr, "myvcs: writing %s to %s\n", object.type, path);
		Buffer compressed = zlib_compress(object.size, object.data);

		FILE *f = fopen(path, "wb");
		if (f == NULL) {
			fprintf(stderr, "error: could not open %s\n", path);
			exit(1);
		}
		fwrite(compressed.data, compressed.size, 1, f);
		fclose(f);

		free(compressed.data);

		chmod(path, 0444); // Read only objects
	}
}

bool myvcs_object_check_type(const char* type) {
	return type != NULL && (
	           strcmp(type, "blob") == 0 ||
	           strcmp(type, "tree") == 0 ||
	           strcmp(type, "commit") == 0 ||
	           strcmp(type, "tag") == 0
	       );
}

Index myvcs_index_read(void) {
	if (!file_exists(DATABASE_DIRECTORY "/index")) {
		return EMPTY_INDEX;
	}

	FILE* f = fopen(DATABASE_DIRECTORY "/index", "rb");
	if (f == NULL) {
		fprintf(stderr, "error: could not open " DATABASE_DIRECTORY "/index\n");
		exit(1);
	}

	char signature[4];
	fread(signature, 1, 4, f);

	if (strncmp(signature, "DIRC", 4) != 0) {
		fprintf(stderr, "error: corrupted index\n");
		exit(1);
	}

	Index index = {0};

	uint32_t version;
	fread(&version, 4, 1, f);
	index.version = ntohl(version);

	if (index.version != 2) {
		fprintf(stderr, "error: unsupported index version\n");
		exit(1);
	}

	uint32_t count;
	fread(&count, 4, 1, f);
	index.count = ntohl(count);

	index.capacity = index.count;
	index.entries = malloc(index.count * sizeof(IndexEntry));

	for (uint32_t i = 0; i < index.count; i++) {
		uint32_t ctime_s, ctime_ns;
		fread(&ctime_s, 4, 1, f);
		index.entries[i].ctime_s = ntohl(ctime_s);

		fread(&ctime_ns, 4, 1, f);
		index.entries[i].ctime_ns = ntohl(ctime_ns);

		uint32_t mtime_s, mtime_ns;
		fread(&mtime_s, 4, 1, f);
		index.entries[i].mtime_s = ntohl(mtime_s);

		fread(&mtime_ns, 4, 1, f);
		index.entries[i].mtime_ns = ntohl(mtime_ns);

		uint32_t dev, ino, mode, uid, gid;
		fread(&dev, 4, 1, f);
		index.entries[i].dev = ntohl(dev);

		fread(&ino, 4, 1, f);
		index.entries[i].ino = ntohl(ino);

		fread(&mode, 4, 1, f);
		index.entries[i].mode = ntohl(mode);

		fread(&uid, 4, 1, f);
		index.entries[i].uid = ntohl(uid);

		fread(&gid, 4, 1, f);
		index.entries[i].gid = ntohl(gid);

		uint32_t file_size;
		fread(&file_size, 4, 1, f);
		index.entries[i].file_size = ntohl(file_size);

		fread(index.entries[i].hash, 20, 1, f);

		uint16_t flags;
		fread(&flags, 2, 1, f);
		index.entries[i].flags = ntohs(flags);

		size_t path_length = index.entries[i].flags & 0x0FFF;
		if (path_length == 0xFFF) {
			fprintf(stderr, "error: path length is too large\n");
			exit(1);
		}

		char* file_path = malloc(path_length+1);
		fread(file_path, path_length, 1, f);
		file_path[path_length] = '\0';

		index.entries[i].path = file_path;

		// Padding
		size_t entry_size = (62 + path_length + 8) & ~(size_t)7;
		size_t padding    = entry_size - 62 - path_length;


		fseek(f, (long)padding, SEEK_CUR);
	}

	// Reading hash
	fread(index.hash, 20, 1, f);

	char hex[41];
	hash_to_string(index.hash, hex);

	fprintf(stderr, "myvcs: index hash: %s\n", hex);

	// TODO: verify checksum

	fclose(f);

	return index;
}

void myvcs_index_add(Index* index, IndexEntry entry) {
	if (index->capacity < index->count + 1) {
		size_t new_capacity = (index->capacity == 0) ? 1 : index->capacity*2;
		IndexEntry* entries = realloc(index->entries, new_capacity*sizeof(IndexEntry));
		assert(entries != NULL);
		index->entries = entries;
		index->capacity = new_capacity;
	}

	index->entries[index->count++] = entry;
}

int myvcs_index_entry_compare(const void* a, const void* b) {
	const IndexEntry* entry1 = a;
	const IndexEntry* entry2 = b;
	return strcmp(entry1->path, entry2->path);
}

void myvcs_index_write(Index index) {
	// Sort paths
	qsort(index.entries, index.count, sizeof(IndexEntry), myvcs_index_entry_compare);

	size_t buffer_cap = 12 + 20;
	for (uint32_t i = 0; i < index.count; i++)
		buffer_cap += (62 + strlen(index.entries[i].path) + 8) & ~(size_t)7;

	uint8_t* write_buffer = malloc(buffer_cap);

	FILE* f = fopen(DATABASE_DIRECTORY "/index.lock", "wb");
	if (f == NULL) {
		fprintf(stderr, "error: could not open " DATABASE_DIRECTORY "/index.lock\n");
		exit(1);
	}

	size_t offset = 0;

	// Signature
	memcpy(write_buffer + offset, "DIRC", 4);
	offset += 4;

	uint32_t version = htonl(index.version);
	memcpy(write_buffer + offset, &version, 4);
	offset += 4;

	uint32_t count = htonl(index.count);
	memcpy(write_buffer + offset, &count, 4);
	offset += 4;

	for (uint32_t i = 0; i < index.count; i++) {
		IndexEntry entry = index.entries[i];

		uint32_t ctime_s = htonl(entry.ctime_s);
		memcpy(write_buffer + offset, &ctime_s, 4);
		offset += 4;

		uint32_t ctime_ns = htonl(entry.ctime_ns);
		memcpy(write_buffer + offset, &ctime_ns, 4);
		offset += 4;

		uint32_t mtime_s = htonl(entry.mtime_s);
		memcpy(write_buffer + offset, &mtime_s, 4);
		offset += 4;

		uint32_t mtime_ns = htonl(entry.mtime_ns);
		memcpy(write_buffer + offset, &mtime_ns, 4);
		offset += 4;

		uint32_t dev = htonl(entry.dev);
		memcpy(write_buffer + offset, &dev, 4);
		offset += 4;

		uint32_t ino = htonl(entry.ino);
		memcpy(write_buffer + offset, &ino, 4);
		offset += 4;

		uint32_t mode = htonl(entry.mode);
		memcpy(write_buffer + offset, &mode, 4);
		offset += 4;

		uint32_t uid = htonl(entry.uid);
		memcpy(write_buffer + offset, &uid, 4);
		offset += 4;

		uint32_t gid = htonl(entry.gid);
		memcpy(write_buffer + offset, &gid, 4);
		offset += 4;

		uint32_t file_size = htonl(entry.file_size);
		memcpy(write_buffer + offset, &file_size, 4);
		offset += 4;

		memcpy(write_buffer + offset, index.entries[i].hash, 20);
		offset += 20;

		size_t path_length = strlen(entry.path);
		if (path_length >= 0xFFF) {
			fprintf(stderr, "error: path too long\n");
			exit(1);
		}

		uint16_t flags = htons((entry.flags & 0xF000) | path_length);
		memcpy(write_buffer + offset, &flags, 2);
		offset += 2;

		memcpy(write_buffer + offset, entry.path, path_length);
		offset += path_length;

		// Padding
		size_t entry_size = (62 + path_length + 8) & ~(size_t)7;
		size_t padding    = entry_size - 62 - path_length;

		memcpy(write_buffer + offset, &zeroes, padding);
		offset += padding;
	}

	// Checksum
	uint8_t hash[20];
	sha1(offset, write_buffer, hash);
	memcpy(write_buffer+offset, hash, 20);
	offset += 20;

	assert(offset == buffer_cap);

	if (fwrite(write_buffer, 1, offset, f) != offset || fclose(f) != 0) {
		fprintf(stderr, "error: failed writing index\n");
		exit(1);
	}

	if (rename(DATABASE_DIRECTORY "/index.lock", DATABASE_DIRECTORY "/index") != 0) {
		fprintf(stderr, "error: could not update index\n");
		exit(1);
	}

	free(write_buffer);
}

uint32_t mode_from_state(mode_t mode) {
	if (S_ISLNK(mode)) {
		return FILE_MODE_SYMLINK;
	}

	if (S_ISREG(mode)) {
		return (mode & S_IXUSR) ? FILE_MODE_EXECUTABLE : FILE_MODE_REGULAR;
	}

	if (S_ISDIR(mode)) {
		return FILE_MODE_DIRECTORY;
	}

	return 0;
}

TreeNode* myvcs_tree_build(Index index, size_t start, size_t end, size_t prefix_len) {
	TreeNode* root = malloc(sizeof(TreeNode));
	if (root == NULL) {
		fprintf(stderr, "error: could not allocate tree\n");
		return NULL;
	}
	memset(root, 0, sizeof(TreeNode));

	size_t tree_size = 0;
	size_t current = start;

	while (current < end) {
		const IndexEntry entry = index.entries[current];
		const char* path = entry.path + prefix_len;
		const char* slash = strchr(path, '/');

		if (slash == NULL) { // File in this directory
			TreeNode* leaf = malloc(sizeof(TreeNode));
			if (leaf == NULL) {
				fprintf(stderr, "error: could not allocate tree\n");
				return NULL;
			}
			memset(leaf, 0, sizeof(TreeNode));

			leaf->name = path;
			leaf->name_length = strlen(leaf->name);
			leaf->mode = entry.mode;
			memcpy(leaf->hash, entry.hash, 20);
			array_append(&root->children, leaf);

			tree_size += snprintf(NULL, 0, "%o %.*s", entry.mode, (int)leaf->name_length, leaf->name) + 1;
			tree_size += 20;

			current++;
		} else { // File subdirectory

			// Finding all files of this folder
			size_t dir_len = slash - path;
			size_t j = current+1;
			while (j < end) {
				const char* sub_entry = index.entries[j].path + prefix_len;
				if (strncmp(sub_entry, path, dir_len) != 0 || sub_entry[dir_len] != '/') break;
				j++;
			}

			TreeNode* child_tree = myvcs_tree_build(index, current, j, prefix_len + dir_len + 1);
			child_tree->name = path;
			child_tree->name_length = dir_len;
			child_tree->mode = FILE_MODE_DIRECTORY;
			array_append(&root->children, child_tree);

			tree_size += snprintf(NULL, 0, "%o %.*s", child_tree->mode, (int)child_tree->name_length, child_tree->name) + 1;
			tree_size += 20;

			current = j;
		}
	}
	root->size = tree_size;

	// Creating Tree Object
	size_t header_size = snprintf(NULL, 0, "tree %zu", tree_size);
	size_t object_size = header_size + tree_size + 1;

	uint8_t* object_data = malloc(object_size);
	if (object_data == NULL) {
		fprintf(stderr, "error: could not allocate buffer\n");
		exit(1);
	}

	snprintf((char*)object_data, object_size,  "tree %zu", tree_size);

	size_t offset = header_size + 1;
	for (size_t i = 0; i < root->children.length; i++) {
		const TreeNode* node = root->children.items[i];
		size_t n = snprintf((char*)object_data + offset, object_size, "%o %.*s", node->mode, (int)node->name_length, node->name);
		offset += n+1;
		memcpy(object_data + offset, node->hash, 20);
		offset += 20;
	}

	root->object = (Object) {
		"tree", object_size, object_data
	};

	sha1(object_size, object_data, root->hash);

	return root;
}

void myvcs_tree_write(TreeNode* root) {
	assert(root != NULL);

	for (size_t i = 0; i < root->children.length; i++) {
		TreeNode* node = root->children.items[i];
		if (node->mode == FILE_MODE_DIRECTORY) myvcs_tree_write(node);
	}
	char hex[41];
	hash_to_string(root->hash, hex);

	fprintf(stderr, "myvcs: writing tree: %s\n", hex);
	myvcs_object_write(hex, root->object);
}

void myvcs_tree_print(Object object, FILE* f) {
	assert(memcmp(object.type, "tree", 4) == 0);

	size_t offset = 0;
	while (offset < object.size) {
		const char* space = memchr(object.data + offset, ' ', object.size - offset);
		if (space == NULL) {
			fprintf(stderr, "error: corrupted object\n");
			exit(1);
		}
		const uint32_t mode = strtoul((char*)object.data + offset, NULL, 8);

		const char* name = space + 1;
		const char* nul = memchr(name, '\0', object.size);
		if (nul == NULL || (size_t)((object.data + object.size) - ((uint8_t*)nul + 1)) < 20) {
			fprintf(stderr, "error: corrupted object\n");
			exit(1);
		}

		const uint8_t* hash = (uint8_t*)nul + 1;
		char hex[41];
		hash_to_string(hash, hex);

		const char* type = (mode == FILE_MODE_DIRECTORY) ? "tree"
		                   : (mode == FILE_MODE_SUBMODULE) ? "commit" : "blob";
		fprintf(f, "%06o %s %s\t%.*s\n", mode, type, hex, (int)(nul - name), name);

		offset = (hash + 20) - object.data;
	}
}

Buffer zlib_compress(size_t size, const void* data) {
	fprintf(stderr, "myvcs: compressing %zu\n", size);

	size_t compressed_size = compressBound(size);
	uint8_t* compressed_data = malloc(compressed_size);
	assert(compressed_data != NULL);

	if (compress(compressed_data, &compressed_size, data, size) != Z_OK) {
		fprintf(stderr, "error: compression failed\n");
		exit(1);
	}

	return (Buffer) {
		compressed_size, compressed_data
	};
}

Buffer zlib_uncompress(size_t size, const void* data) {
	fprintf(stderr, "myvcs: decompressing %zu\n", size);
	size_t capacity = size * 4 + 64; // Initial guess

	uint8_t* decompressed_data = malloc(capacity);
	assert(decompressed_data != NULL);

	while (true) {
		size_t decompressed_size = capacity;
		int rc = uncompress(decompressed_data, &decompressed_size, data, size);

		if (rc == Z_OK) {
			return (Buffer) {
				decompressed_size, decompressed_data
			};
		}

		// corrupt data or out of memory
		if (rc != Z_BUF_ERROR) {
			fprintf(stderr, "error: decompression failed\n");
			exit(1);
		}

		// too small: grow and retry
		capacity *= 2;
		uint8_t* buf = realloc(decompressed_data, capacity);
		assert(buf != NULL);
		decompressed_data = buf;
	}
}
