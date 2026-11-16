#include "sha1.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static inline uint32_t rotate_left(uint32_t x, int n) {
	return (x << n) | (x >> (32 - n));
}

// copied from https://en.wikipedia.org/wiki/SHA-1
void sha1(uint64_t n, const uint8_t* message, uint8_t hash[20]) {
	assert(hash != NULL);

	// Pre-Processing
	uint64_t ml = n*8;
	size_t buffer_size = ((n + 9 + 63) / 64) * 64; // ceil((n + 9) / 64) × 64
	uint8_t* buffer = malloc(buffer_size);
    assert(buffer != NULL);

	memcpy(buffer, message, n);

	size_t k = n;
	buffer[k++] = 0x80;

	while (k % 64 != 56) {
		buffer[k++] = 0x00;
	}

	// Big Endian copy
	for (int i = 0; i < 8; i++) {
		buffer[k++] = (uint8_t)(ml >> (56 - 8*i));
	}

	assert(k == buffer_size);

	size_t chunks = buffer_size / 64;
	uint32_t words[80]; // Big Endian

	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	// Process the message in successive 512-bit chunks
	for (size_t chunki = 0; chunki < chunks; ++chunki) {
		uint8_t* chunk = (buffer + chunki*64);

		// break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
		for (int i = 0; i < 16; ++i) {
			words[i] = (uint32_t)chunk[i*4] << 24 | (uint32_t)chunk[i*4+1] << 16 | (uint32_t)chunk[i*4+2] << 8 | (uint32_t)chunk[i*4+3];
		}

		// extend the sixteen 32-bit words into eighty 32-bit words
		for (int i = 16; i < 80; ++i) {
			words[i] = rotate_left(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1);
		}

		// Initialize hash value for this chunk:
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		for (int i = 0; i < 80; ++i) {
			uint32_t f = 0;
			uint32_t pos = 0;

			if (0 <= i && i <= 19) {
				f = (b & c) | (~b & d);
				pos = 0x5A827999;
			} else if (20  <= i && i  <= 39) {
				f = b ^ c ^ d;
				pos = 0x6ED9EBA1;
			} else if (40  <= i && i  <= 59) {
				f = (b & c) | (b & d) | (c & d);
				pos = 0x8F1BBCDC;
			} else if (60  <= i && i  <= 79) {
				f = b ^ c ^ d;
				pos = 0xCA62C1D6;
			}

			uint32_t temp = rotate_left(a, 5) + f + e + pos + words[i];
			e = d;
			d = c;
			c = rotate_left(b, 30);
			b = a;
			a = temp;
		}

		// Add this chunk's hash to result so far:
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
	}
	free(buffer);

	// hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
	uint32_t h[5] = { h0, h1, h2, h3, h4 };
	for (int i = 0; i < 5; ++i) {
		hash[i*4]   = (uint8_t)(h[i] >> 24);
		hash[i*4+1] = (uint8_t)(h[i] >> 16);
		hash[i*4+2] = (uint8_t)(h[i] >> 8);
		hash[i*4+3] = (uint8_t)(h[i]);
	}
}

void hash_to_string(const uint8_t hash[20], char hash_str[41]) {
	static const char HEX[] = "0123456789abcdef";

	for (int i = 0; i < 20; ++i) {
		hash_str[i*2] = HEX[(hash[i] >> 4) & 0x0F];
		hash_str[i*2+1] = HEX[hash[i] & 0x0F];
	}

	hash_str[40] = '\0';
}
