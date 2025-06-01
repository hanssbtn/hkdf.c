#include "../include/hkdf.h"
#include <math.h>

int32_t hkdf_convert_from_key(hkdf_result_t *result, const char *const k, ssize_t len) {
	if (!k || !result) return -1;
	switch (result->key_type) {
		case HKDF_TYPE_TAG_CURVE25519_KEY: {
			if (len > 64) return -4;
			memcpy(result->key.key8, k, len);
		} break;
		case HKDF_TYPE_TAG_VEC8: {
			if (!result->vec8.bytes || result->vec8.length < len) {
				if (!k) return -1;
				uint8_t *tmp = realloc(result->vec8.bytes, sizeof(uint8_t) * len);
				if (!tmp) return -2;
				result->vec8.bytes = tmp;
				result->vec8.size = len;
			}
			memcpy(result->vec8.bytes, k, len);
			result->vec8.length = len;
		} break;
	}
	return 0;
}

int32_t hkdf_hmac_hash(
	uint8_t *result, // result
	sha512_context_t *const ctx,
	const uint8_t *const restrict K, // authentication key
	const ssize_t K_len,
	const uint8_t *const restrict text,
	const ssize_t text_len,
	hkdf_hash_function_t H // hash function used (SHA512 / SHA384) 
) {
	if (!ctx || !result || !text || !K) return -1;
	ssize_t L; // hash output length in bytes
	ssize_t B; // hash function message block length in bytes
	
	// Step 1
	switch (H) {
		case HKDF_HASH_FUNC_SHA384: {
			sha384_ctx_init(ctx);
			L = 48;
			B = 128;
		} break;
		case HKDF_HASH_FUNC_SHA512: {
			sha512_ctx_init(ctx);
			L = 64;
			B = 128;
		} break;
		default: {
			return -3;
		}
	}
	uint8_t ipad[B], opad[B], bytes[B];
	uint8_t tmp[L];
	if (K_len > B) {
		sha512_ctx_update(ctx, K, K_len);
		sha512_ctx_final(ctx, bytes, L);
		memset(bytes + L, 0, B - L);
	} else {
		memcpy(bytes, K, K_len);
		memset(bytes + K_len, 0, B - K_len);
	}
	// Step 2
	for (ssize_t i = 0; i < B; ++i) {
		ipad[i] = bytes[i] ^ 0x36;
		opad[i] = bytes[i] ^ 0x5C;
	}

	switch (H) {
        case HKDF_HASH_FUNC_SHA384: sha384_ctx_init(ctx); break;
        case HKDF_HASH_FUNC_SHA512: sha512_ctx_init(ctx); break;
    }
	// Step 3
	// Step 4
	sha512_ctx_update(ctx, ipad, B);
	sha512_ctx_update(ctx, text, text_len);
	sha512_ctx_final(ctx, tmp, L);
	// Step 6
	switch (H) {
        case HKDF_HASH_FUNC_SHA384: sha384_ctx_init(ctx); break;
        case HKDF_HASH_FUNC_SHA512: sha512_ctx_init(ctx); break;
    }
	sha512_ctx_update(ctx, opad, B);
	sha512_ctx_update(ctx, tmp, L);
	sha512_ctx_final(ctx, result, L);
	return 0;
}

int32_t hkdf_extract(
	uint8_t *const restrict prk, 
	ssize_t prk_len,
	const uint8_t *const restrict ikm, 
	ssize_t ikm_len, 
	const uint8_t *restrict const salt, 
	ssize_t salt_len, 
	hkdf_hash_function_t hf
) {
	if (!prk || !ikm || (!salt && salt_len > 0) || (salt && salt_len <= 0)) return -1;
	sha512_context_t ctx;
	ssize_t slen = salt ? salt_len : 64; 
	uint8_t *s = malloc(sizeof(uint8_t) * slen);
	if (!s) {
		return -2;
	}
	switch (hf) {
		case HKDF_HASH_FUNC_SHA384: {
			if (prk_len < 48) {
				free(s);
				return -4;
			}
			if (!salt) {
				memset(s, 0, 48);
				slen = 48;
			} else {
				memcpy(s, salt, salt_len);
				slen = salt_len;
			}
		} break;
		case HKDF_HASH_FUNC_SHA512: {
			if (prk_len < 64) {
				free(s);
				return -4;
			}
			if (!salt) {
				memset(s, 0, 64);
				slen = 64;
			} else {
				memcpy(s, salt, salt_len);
				slen = salt_len;
			}
		} break;
		default: {
			free(s);
			return -4;
		}
	}

	int res = hkdf_hmac_hash(prk, &ctx, s, slen, ikm, ikm_len, hf);
	
	free(s);
	return res;
}

int32_t hkdf_expand(
	uint8_t *const restrict okm, 
	const ssize_t key_length,
	const uint8_t *const restrict prk, 
	ssize_t prk_length, 
	const char *const info, 
	const ssize_t info_length, 
	hkdf_hash_function_t hf
) {
	if (!okm || !prk || (!info && info_length > 0) || (info && info_length <= 0)) return -1;
	if (prk_length <= 0|| key_length < 0) return -4;
	if (!key_length) return 0;
	ssize_t hash_length = 0;
	switch (hf) {
		case HKDF_HASH_FUNC_SHA384: {
			hash_length = 48;
		} break;
		case HKDF_HASH_FUNC_SHA512: {
			hash_length = 64;
		} break; 
		default: {
			return -4;
		}
	}
	ssize_t N = (ssize_t)ceil(((double)key_length) / ((double)prk_length));
	printf("N: %lld\n", N);
	printf("key_length: %lld\n", key_length);
	sha512_context_t ctx;
	uint8_t *Tcurr = malloc(sizeof(uint8_t) * (prk_length + info_length + 8)), *Tprev = malloc(sizeof(uint8_t) * (prk_length + info_length + 8));
	if (!Tcurr || !Tprev) {
		if (Tcurr) free(Tcurr);
		if (Tprev) free(Tprev);
		return -2;
	}
	memcpy(Tprev, info, info_length);
	uint8_t octet = 0x01;
	Tprev[info_length] = octet;
	ssize_t Tprev_length = info_length + 1;
	hkdf_hmac_hash(Tcurr, &ctx, prk, prk_length, Tprev, Tprev_length, hf);
	Tprev_length += hash_length;
	memcpy(Tprev, Tcurr, hash_length);
	memcpy(Tprev + hash_length, info, info_length);
	uint8_t *tmp = Tcurr;
	Tcurr = Tprev;
	Tprev = tmp;
	octet++;
	Tprev[hash_length + info_length] = octet;
	for (ssize_t i = 1; i < N; ++i) {
		hkdf_hmac_hash(Tcurr, &ctx, prk, prk_length, Tprev, Tprev_length, hf);
		tmp = Tcurr;
		Tcurr = Tprev;
		Tprev = tmp;
		memcpy(Tprev, Tcurr, hash_length);
		memcpy(Tprev + hash_length, info, info_length);
		octet++;
		Tprev[hash_length + info_length] = octet;
	}
	memcpy(okm, Tcurr, key_length);
	free(Tcurr);
	free(Tprev);
	return 0;
}