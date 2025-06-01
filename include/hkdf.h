#pragma once
#ifndef HKDF_H__
#define HKDF_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include "../curve25519.c/include/curve25519.h"
#include "../sha512.c/include/sha512.h"

typedef enum {
	HKDF_HASH_FUNC_SHA512 = 0,
	HKDF_HASH_FUNC_SHA384 = 1
} hkdf_hash_function_t;

typedef enum {
	HKDF_TYPE_TAG_CURVE25519_KEY,
	HKDF_TYPE_TAG_VEC8,
} hkdf_key_type_tag_t;

typedef struct {
	hkdf_key_type_tag_t key_type;
	union {
		curve25519_key_t key;
		struct {
			ssize_t length, size;
			uint8_t *bytes;
		} vec8;
	};
} hkdf_result_t;

typedef hkdf_result_t hkdf_source_t;

int32_t hkdf_convert_from_key(hkdf_result_t *const src, const char *const k, ssize_t len);
int32_t hkdf_extract(uint8_t *const restrict prk, ssize_t prk_len, const uint8_t *const restrict key, const ssize_t key_length, const uint8_t *restrict const text, const ssize_t text_length, hkdf_hash_function_t hf);
int32_t hkdf_expand(uint8_t *const restrict okm, const uint8_t *const restrict prk, ssize_t prk_length, const char *const info, const ssize_t key_length);

#endif // HKDF_H__