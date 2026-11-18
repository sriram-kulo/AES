# EX-8-ADVANCED-ENCRYPTION-STANDARD ALGORITHM
# Aim:
To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

# ALGORITHM:
AES is based on a design principle known as a substitution–permutation.
AES does not use a Feistel network like DES, it uses variant of Rijndael.
It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
AES operates on a 4 × 4 column-major order array of bytes, termed the state
# PROGRAM:
```
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* AES-256-GCM URL token format: base64url(nonce || ciphertext || tag).
   Build with: gcc exp8.c -o exp8 -lcrypto
   Usage: exp8 encrypt <64-hex-digit-key> <URL>
		  exp8 decrypt <64-hex-digit-key> <token>
*/
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	c = (char)tolower((unsigned char)c);
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

static int parse_key(const char *text, unsigned char key[KEY_LEN])
{
	if (strlen(text) != KEY_LEN * 2) return 0;
	for (int i = 0; i < KEY_LEN; ++i) {
		int hi = hex_value(text[i * 2]);
		int lo = hex_value(text[i * 2 + 1]);
		if (hi < 0 || lo < 0) return 0;
		key[i] = (unsigned char)((hi << 4) | lo);
	}
	return 1;
}

static char *base64url_encode(const unsigned char *data, size_t len)
{
	if (len > INT_MAX - 2) return NULL;
	size_t cap = 4 * ((len + 2) / 3);
	char *out = (char *)malloc(cap + 1);
	if (!out) return NULL;
	int n = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
	if (n < 0) { free(out); return NULL; }
	while (n > 0 && out[n - 1] == '=') --n;
	for (int i = 0; i < n; ++i) {
		if (out[i] == '+') out[i] = '-';
		else if (out[i] == '/') out[i] = '_';
	}
	out[n] = '\0';
	return out;
}

static unsigned char *base64url_decode(const char *text, size_t *out_len)
{
	size_t len = strlen(text);
	if (len > INT_MAX || len % 4 == 1) return NULL;
	size_t padded_len = (len + 3) & ~(size_t)3;
	char *tmp = (char *)malloc(padded_len + 1);
	unsigned char *out = (unsigned char *)malloc((padded_len / 4) * 3 + 1);
	if (!tmp || !out) { free(tmp); free(out); return NULL; }
	for (size_t i = 0; i < len; ++i) {
		if (!(isalnum((unsigned char)text[i]) || text[i] == '-' || text[i] == '_')) {
			free(tmp); free(out); return NULL;
		}
		tmp[i] = text[i] == '-' ? '+' : (text[i] == '_' ? '/' : text[i]);
	}
	for (size_t i = len; i < padded_len; ++i) tmp[i] = '=';
	tmp[padded_len] = '\0';
	int n = EVP_DecodeBlock(out, (const unsigned char *)tmp, (int)padded_len);
	free(tmp);
	if (n < 0) { free(out); return NULL; }
	size_t pad = padded_len - len;
	*out_len = (size_t)n - pad;
	return out;
}

static int encrypt_url(const unsigned char key[KEY_LEN], const char *url)
{
	size_t url_len = strlen(url);
	if (url_len > INT_MAX) return 0;
	unsigned char nonce[NONCE_LEN];
	unsigned char *payload = (unsigned char *)malloc(NONCE_LEN + url_len + TAG_LEN);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int out_len = 0, total = 0, ok = 0;
	if (!payload || !ctx || RAND_bytes(nonce, sizeof nonce) != 1) goto done;
	memcpy(payload, nonce, NONCE_LEN);
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
		EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
		EVP_EncryptUpdate(ctx, payload + NONCE_LEN, &out_len,
						  (const unsigned char *)url, (int)url_len) != 1)
		goto done;
	total = out_len;
	if (EVP_EncryptFinal_ex(ctx, payload + NONCE_LEN + total, &out_len) != 1)
		goto done;
	total += out_len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
							payload + NONCE_LEN + total) != 1)
		goto done;
	char *token = base64url_encode(payload, NONCE_LEN + (size_t)total + TAG_LEN);
	if (!token) goto done;
	puts(token);
	free(token);
	ok = 1;
done:
	EVP_CIPHER_CTX_free(ctx);
	if (payload) { OPENSSL_cleanse(payload, NONCE_LEN + url_len + TAG_LEN); free(payload); }
	return ok;
}

static int decrypt_url(const unsigned char key[KEY_LEN], const char *token)
{
	size_t payload_len = 0;
	unsigned char *payload = base64url_decode(token, &payload_len);
	if (!payload || payload_len < NONCE_LEN + TAG_LEN ||
		payload_len - NONCE_LEN - TAG_LEN > INT_MAX) {
		free(payload);
		return 0;
	}
	size_t cipher_len = payload_len - NONCE_LEN - TAG_LEN;
	unsigned char *plain = (unsigned char *)malloc(cipher_len + 1);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int out_len = 0, total = 0, ok = 0;
	if (!plain || !ctx) goto done;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
		EVP_DecryptInit_ex(ctx, NULL, NULL, key, payload) != 1 ||
		EVP_DecryptUpdate(ctx, plain, &out_len, payload + NONCE_LEN,
						  (int)cipher_len) != 1)
		goto done;
	total = out_len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
							payload + NONCE_LEN + cipher_len) != 1 ||
		EVP_DecryptFinal_ex(ctx, plain + total, &out_len) != 1)
		goto done;
	total += out_len;
	plain[total] = '\0';
	puts((const char *)plain);
	ok = 1;
done:
	EVP_CIPHER_CTX_free(ctx);
	if (plain) { OPENSSL_cleanse(plain, cipher_len + 1); free(plain); }
	OPENSSL_cleanse(payload, payload_len);
	free(payload);
	return ok;
}

static void read_line(const char *prompt, char *buf, size_t size)
{
	printf("%s", prompt);
	fflush(stdout);
	if (!fgets(buf, (int)size, stdin)) { buf[0] = '\0'; return; }
	buf[strcspn(buf, "\r\n")] = '\0';
}

int main(int argc, char **argv)
{
	unsigned char key[KEY_LEN];
	char mode_buf[32], key_buf[128], data_buf[4096];
	const char *mode, *key_text, *data;
	int ok = 0;

	if (argc == 4) {                      /* command-line mode */
		mode = argv[1]; key_text = argv[2]; data = argv[3];
	} else if (argc == 1) {               /* interactive mode */
		read_line("Operation (encrypt/decrypt): ", mode_buf, sizeof mode_buf);
		read_line("Key (64 hex digits): ", key_buf, sizeof key_buf);
		if (strcmp(mode_buf, "encrypt") == 0)
			read_line("Enter URL: ", data_buf, sizeof data_buf);
		else
			read_line("Enter token: ", data_buf, sizeof data_buf);
		mode = mode_buf; key_text = key_buf; data = data_buf;
	} else {
		fprintf(stderr, "Usage: %s [encrypt|decrypt <64-hex-digit-key> <URL-or-token>]\n", argv[0]);
		return 1;
	}

	if (!parse_key(key_text, key)) {
		fprintf(stderr, "Invalid key: it must be exactly 64 hex digits.\n");
		return 1;
	}
	if (strcmp(mode, "encrypt") == 0) ok = encrypt_url(key, data);
	else if (strcmp(mode, "decrypt") == 0) ok = decrypt_url(key, data);
	else fprintf(stderr, "Operation must be encrypt or decrypt.\n");

	OPENSSL_cleanse(key, sizeof key);
	OPENSSL_cleanse(key_buf, sizeof key_buf);
	if (!ok) fprintf(stderr, "Operation failed (invalid input or authentication failure).\n");
	return ok ? 0 : 1;
}

```
# OUTPUT:
<img width="647" height="135" alt="image" src="https://github.com/user-attachments/assets/f1963903-e7e0-4178-8aab-bd5bf2cf67ca" />
<img width="640" height="138" alt="image" src="https://github.com/user-attachments/assets/b86ed4e7-764d-4c36-a953-93ed23a6ffec" />
# RESULT:
In conclusion, the Advanced Encryption Standard (AES) Algorithm implementation was executed successfully.
