#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdbool.h>

void sha1(uint64_t n, const uint8_t* message, uint8_t hash[20]);

// Hash helpers
bool hash_eq(const uint8_t h1[20], const uint8_t h2[20]);
void hash_to_string(const uint8_t hash[20], char hash_str[41]);

#endif