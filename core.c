// core.c - SecureNotes core helpers (file encrypt/decrypt + verifier using libsodium Argon2id)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <dirent.h>
#include <direct.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <io.h>
#define F_OK 0
#define access _access
#define mkdir _mkdir
#else
#include <arpa/inet.h> // for htonl/ntohl on non-windows (if ever)
#endif

#include <sys/stat.h>
#include <sodium.h> // libsodium
#include <zip.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

static unsigned char xchacha_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {0};; // 32-byte key


// Verifier file format (vault file) - versioned
// Layout (binary):
// 0..3   : "SNV1" magic (4 bytes)
// 4      : salt_len (1 byte)           (we use 16)
// 5..12  : opslimit (8 bytes, uint64_t little-endian)
//13..20  : memlimit (8 bytes, uint64_t little-endian)
//21..(21+salt_len-1) : salt (salt_len bytes)
//... following: verifier (32 bytes - HMAC-SHA256 result)
// This layout is purposely simple and versioned so we can upgrade later.

static const char VER_MAGIC[4] = { 'S','N','V','1' };
static const size_t VERIFIER_LEN = 32;
static const size_t SALT_LEN_DEFAULT = 16;
static const uint64_t OPSLIMIT_DEFAULT = 3;              // Argon2 ops (time) - tune as desired
static const uint64_t MEMLIMIT_DEFAULT = 64ULL * 1024 * 1024; // 64 MiB

int Init(void)
{
    return sodium_init();
}

// Utility: combine path (Windows PathCombineA). Returns newly allocated string or NULL.
char* JoinPath(const char* saveDirPath, const char* fileName) {
    assert(saveDirPath != NULL);
    assert(fileName != NULL);

    char buffer_1[MAX_PATH] = "";
#ifdef _WIN32
    char* result = PathCombineA(buffer_1, saveDirPath, fileName);
    if (result == NULL) return NULL;
    size_t result_len = strlen(result);
#else
    // non-windows fallback
    int needed = snprintf(buffer_1, sizeof(buffer_1), "%s/%s", saveDirPath, fileName);
    if (needed < 0 || (size_t)needed >= sizeof(buffer_1)) return NULL;
    size_t result_len = (size_t)needed;
#endif

    char* ret_buff = calloc(result_len + 1, 1);
    if (!ret_buff) return NULL;
    memcpy(ret_buff, buffer_1, result_len);
    return ret_buff;
}

// Utility: extract filename from full path (cross-platform).
// Returns a newly allocated string containing just the file name,
// or NULL on error.
/*
static char* GetFileName(const char* fullPath)
{
    assert(fullPath != NULL);
    if (!fullPath || !*fullPath)
        return NULL;

    const char* lastSlash = strrchr(fullPath, '\\');  // Windows
    const char* lastSlashAlt = strrchr(fullPath, '/'); // Unix-style

    // pick whichever occurs later in the string
    const char* fileNamePtr = lastSlash;
    if (!fileNamePtr || (lastSlashAlt && lastSlashAlt > fileNamePtr))
        fileNamePtr = lastSlashAlt;

    // if no slash found, the path *is* the filename
    if (!fileNamePtr)
        fileNamePtr = fullPath;
    else
        fileNamePtr++; // skip the slash

    size_t len = strlen(fileNamePtr);
    char* fileName = calloc(len + 1, 1);
    if (!fileName)
        return NULL;

    memcpy(fileName, fileNamePtr, len);
    return fileName;
}
*/

// Read entire file into heap buffer. On success returns pointer (must free) and sets *fileLen.
// On failure returns NULL and *fileLen is undefined.
static char* ReadFileAll(const char* filePath, size_t* fileLen) {
    if (!filePath) return NULL;
    FILE *f = fopen(filePath, "rb");
    if (f == NULL) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long ft = ftell(f);
    if (ft < 0) { fclose(f); return NULL; }
    size_t fLen = (size_t)ft;
    rewind(f);

    char* data = calloc(fLen + 1, 1); // +1 to allow null-termination if needed
    if (data == NULL) { fclose(f); return NULL; }

    size_t read = 0;
    while (read < fLen) {
        size_t r = fread(data + read, 1, fLen - read, f);
        if (r == 0) {
            if (feof(f)) break;
            if (ferror(f)) { free(data); fclose(f); return NULL; }
        }
        read += r;
    }
    fclose(f);
    if (fileLen) *fileLen = read;
    return data;
}

// Write dataLen bytes to filePath, returns 0 on success, non-zero on error.
static int WriteFileAll(const char* filePath, const char* data, size_t dataLen) {
    if (!filePath || !data) return 1;
    FILE *f = fopen(filePath, "wb");
    if (f == NULL) return 1;

    size_t written = 0;
    while (written < dataLen) {
        size_t w = fwrite(data + written, 1, dataLen - written, f);
        if (w == 0) {
            if (ferror(f)) { fclose(f); return 1; }
        }
        written += w;
    }
    fflush(f);
    fclose(f);
    return 0;
}

static int GenerateRandomBytes(unsigned char *buffer, size_t len) {
    randombytes_buf(buffer, len);
    return 1;
}

static int IsKeyLoaded(void)
{
    static const unsigned char zero_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {0};
    return sodium_memcmp(xchacha_key, zero_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES) != 0;
}

// ------------------------------------------------------
// 🔹 File I/O helpers
// ------------------------------------------------------

static unsigned char* ReadFileToBuffer(const char* path, size_t* outSize) {
    assert(path && outSize);

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) { fclose(f); return NULL; }
    rewind(f);

    unsigned char* buf = malloc(len);
    if (!buf) { fclose(f); return NULL; }

    size_t read = fread(buf, 1, len, f);
    fclose(f);

    if (read != (size_t)len) {
        free(buf);
        return NULL;
    }

    *outSize = (size_t)len;
    return buf;
}

static int WriteBufferToFile(const char* path, const unsigned char* data, size_t size) {
    assert(path && data);
    FILE* f = fopen(path, "wb");
    if (!f) return 0;

    size_t written = fwrite(data, 1, size, f);
    fclose(f);
    return (written == size);
}

// ------------------------------------------------------
// 🔹 Encryption / Decryption Helpers (IV embedded in buffer)
// ------------------------------------------------------

/* =========================  EncryptBuffer  ========================= */

static unsigned char* EncryptBuffer(const unsigned char* plaintext,
                                    size_t plain_len,
                                    size_t* out_len)
{
    assert(plaintext && out_len);

    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: encryption key not loaded.\n");
        return NULL;
    }

    /* Build payload = [4-byte big-endian length] || plaintext */
    const size_t payload_len = sizeof(uint32_t) + plain_len;
    unsigned char *payload = malloc(payload_len);
    if (!payload) return NULL;

    uint32_t be_len = htonl((uint32_t)plain_len);
    memcpy(payload, &be_len, sizeof(be_len));
    memcpy(payload + sizeof(be_len), plaintext, plain_len);

    /* Output layout: nonce (24 bytes) || ciphertext (payload_len + 16 bytes tag) */
    const size_t buf_cap = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                           payload_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    unsigned char *outbuf = malloc(buf_cap);
    if (!outbuf) { free(payload); return NULL; }

    unsigned char *nonce = outbuf;
    unsigned char *cipher = outbuf + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    GenerateRandomBytes(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    unsigned long long cipher_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher, &cipher_len,
            payload, (unsigned long long)payload_len,
            NULL, 0,           // no associated data
            NULL,              // no secret nonce
            nonce, xchacha_key) != 0)
    {
        free(payload);
        free(outbuf);
        return NULL;
    }

    free(payload);

    if (out_len)
        *out_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (size_t)cipher_len;
    return outbuf;  // caller frees
}

/* =========================  DecryptBuffer  ========================= */

static unsigned char* DecryptBuffer(const unsigned char* in_buf,
                                    size_t in_len,
                                    size_t* out_len)
{
    assert(in_buf && out_len);

    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: encryption key not loaded.\n");
        return NULL;
    }

    const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t min_len   = nonce_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (in_len < min_len) {
        fprintf(stderr, "Invalid encrypted buffer size.\n");
        return NULL;
    }

    const unsigned char *nonce  = in_buf;
    const unsigned char *cipher = in_buf + nonce_len;
    const size_t cipher_len     = in_len - nonce_len;

    unsigned char *payload = malloc(cipher_len);
    if (!payload) return NULL;

    unsigned long long payload_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            payload, &payload_len,
            NULL,                   // no secret nonce
            cipher, (unsigned long long)cipher_len,
            NULL, 0,                // no associated data
            nonce, xchacha_key) != 0)
    {
        free(payload);
        fprintf(stderr, "Authentication failed (corrupted or tampered data).\n");
        return NULL;
    }

    if (payload_len < sizeof(uint32_t)) {
        free(payload);
        fprintf(stderr, "Corrupted data (too short).\n");
        return NULL;
    }

    uint32_t be_len = 0;
    memcpy(&be_len, payload, sizeof(be_len));
    uint32_t plain_len = ntohl(be_len);

    if (plain_len != payload_len - sizeof(uint32_t)) {
        free(payload);
        fprintf(stderr, "Corrupted data (length mismatch).\n");
        return NULL;
    }

    unsigned char *plain = calloc(plain_len + 1, 1);  // +1 for NUL
    if (!plain) { free(payload); return NULL; }

    memcpy(plain, payload + sizeof(uint32_t), plain_len);

    if (out_len)
        *out_len = plain_len;

    free(payload);
    return plain;  // caller frees
}

// ------------------------------------------------------
// 🔹 High-level functions (file handling)
// ------------------------------------------------------

char* ReadFileAndDecrypt(const char* dir, const char* name) {
    assert(dir && name);

    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: key not loaded.\n");
        return NULL;
    }

    char* path = JoinPath(dir, name);
    if (!path) return NULL;

    size_t file_len;
    unsigned char* file_buf = ReadFileToBuffer(path, &file_len);
    free(path);
    if (!file_buf) return NULL;

    size_t plain_len;
    unsigned char* plain = DecryptBuffer(file_buf, file_len, &plain_len);
    if(!plain)
    {
        free(file_buf);
        return NULL;
    }

    free(file_buf);
    return (char*)plain; // caller frees
}

int EncryptAndSaveFile(const char* dir, const char* name, const char* text)
{
    assert(dir && name && text);

    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: key not loaded.\n");
        return 0;
    }

    char* path = JoinPath(dir, name);
    if (!path)
        return 0;

    // --- 1. Check if an identical note already exists ---
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > 0)
    {
        // Try to decrypt existing file
        unsigned char* oldPlain = (unsigned char*)ReadFileAndDecrypt(dir, name);
        if (oldPlain)
        {
            // Compare decrypted contents to new plaintext
            if (strcmp((const char*)oldPlain, text) == 0)
            {
                sodium_memzero(oldPlain, strlen((char*)oldPlain));
                free(oldPlain);
                free(path);
                return 1; // identical — skip re-encryption
            }
            sodium_memzero(oldPlain, strlen((char*)oldPlain));
            free(oldPlain);
        }
    }

    // --- 2. Encrypt new text ---
    size_t enc_len = 0;
    unsigned char* enc_buf = EncryptBuffer((const unsigned char*)text, strlen(text), &enc_len);
    if (!enc_buf)
    {
        free(path);
        return 0;
    }

    // --- 3. Write encrypted data to disk ---
    int ok = WriteBufferToFile(path, enc_buf, enc_len);

    // --- 4. Secure cleanup ---
    sodium_memzero(enc_buf, enc_len);
    free(enc_buf);
    free(path);

    return ok;
}

// Create a vault (verifier) file at checkFilePath using password.
// Returns 0 on success, non-zero on error.
static int CreateVerifierFileAndSetKey(const char* checkFilePath, const char* password) {
    if (!checkFilePath || !password) return 1;

    unsigned char salt[SALT_LEN_DEFAULT];
    randombytes_buf(salt, SALT_LEN_DEFAULT);

    unsigned char derived_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (crypto_pwhash(derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      password, strlen(password),
                      salt,
                      (size_t)OPSLIMIT_DEFAULT,
                      (size_t)MEMLIMIT_DEFAULT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return 1; // out of memory / too slow
    }

    // verifier = HMAC-SHA256(derived_key, "SecureNotes v1 verifier")
    const char *const_str = "SecureNotes v1 verifier";
    unsigned char verifier[VERIFIER_LEN];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)const_str, strlen(const_str));
    crypto_auth_hmacsha256_final(&st, verifier);

    // Build file buffer
    size_t buf_size = 4 + 1 + 8 + 8 + SALT_LEN_DEFAULT + VERIFIER_LEN;
    unsigned char* buf = calloc(1, buf_size);
    if (!buf) { sodium_memzero(derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES); return 1; }

    size_t pos = 0;
    memcpy(buf + pos, VER_MAGIC, 4); pos += 4;
    buf[pos++] = (unsigned char)SALT_LEN_DEFAULT;
    uint64_t ops_le = OPSLIMIT_DEFAULT;
    uint64_t mem_le = MEMLIMIT_DEFAULT;
    // store in little endian for simplicity
    memcpy(buf + pos, &ops_le, sizeof(ops_le)); pos += sizeof(ops_le);
    memcpy(buf + pos, &mem_le, sizeof(mem_le)); pos += sizeof(mem_le);
    memcpy(buf + pos, salt, SALT_LEN_DEFAULT); pos += SALT_LEN_DEFAULT;
    memcpy(buf + pos, verifier, VERIFIER_LEN); pos += VERIFIER_LEN;

    int rc = WriteFileAll(checkFilePath, (char*)buf, pos);

    // set key
    memcpy(xchacha_key, derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    
    sodium_memzero(derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    sodium_memzero(verifier, VERIFIER_LEN);
    free(buf);
    return rc;
}

// Securely wipes in-memory key and any derived secrets.
// Call this when the user logs out.
void Logout(void)
{
    // Overwrite the global key with zeros.
    sodium_memzero(xchacha_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    printf("User logged out. Key securely cleared.\n");
}

// Check verifier file and if ok, fill global 'key' with derived key and return 1.
// Returns 0 on wrong password or error.
int CheckPasswordAndDeriveEncKey(const char *password, const char* checkDirPath, const char* checkFileName)
{
    if (!password || !checkDirPath || !checkFileName) {
        Logout();
        return 0;
    }

    char* filePath = JoinPath(checkDirPath, checkFileName);
    if (!filePath) {
        Logout();
        return 0;
    }

    // First-run: create verifier if it does not exist
    if (access(filePath, F_OK) != 0) {
        if (CreateVerifierFileAndSetKey(filePath, password) != 0) {
            free(filePath);
            return 1;
        }
    }

    // Read verifier file
    size_t fileLen = 0;
    char* fileBuf = ReadFileAll(filePath, &fileLen);
    free(filePath);
    if (!fileBuf) {
        Logout();
        return 0;
    }

    // Basic validation
    size_t pos = 0;
    if (fileLen < 4 + 1 + 8 + 8 + 1 + VERIFIER_LEN || memcmp(fileBuf + pos, VER_MAGIC, 4) != 0) {
        free(fileBuf);
        Logout();
        return 0;
    }
    pos += 4;

    unsigned char salt_len = (unsigned char)fileBuf[pos++];
    if (salt_len < 8 || salt_len > 64 || fileLen < 4 + 1 + 8 + 8 + salt_len + VERIFIER_LEN) {
        free(fileBuf);
        Logout();
        return 0;
    }

    uint64_t ops_le = 0, mem_le = 0;
    memcpy(&ops_le, fileBuf + pos, sizeof(ops_le)); pos += sizeof(ops_le);
    memcpy(&mem_le, fileBuf + pos, sizeof(mem_le)); pos += sizeof(mem_le);

    unsigned char salt[64];
    memcpy(salt, fileBuf + pos, salt_len); pos += salt_len;

    unsigned char stored_verifier[VERIFIER_LEN];
    memcpy(stored_verifier, fileBuf + pos, VERIFIER_LEN);

    // Derive key from password
    unsigned char derived_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (crypto_pwhash(derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      password, strlen(password),
                      salt,
                      (size_t)ops_le,
                      (size_t)mem_le,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(fileBuf);
        Logout();
        return 0;
    }

    // Compute verifier and compare
    const char *const_str = "SecureNotes v1 verifier";
    unsigned char computed_verifier[VERIFIER_LEN];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)const_str, strlen(const_str));
    crypto_auth_hmacsha256_final(&st, computed_verifier);

    int ok = (sodium_memcmp(computed_verifier, stored_verifier, VERIFIER_LEN) == 0);
    if (ok) {
        memcpy(xchacha_key, derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    } else {
        Logout();
    }

    // Cleanup
    sodium_memzero(derived_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    sodium_memzero(computed_verifier, VERIFIER_LEN);
    sodium_memzero(stored_verifier, VERIFIER_LEN);
    free(fileBuf);

    return ok;
}



// Check if password verifier file exists (split path convenience)
int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName) {
    if (!checkDirPath || !checkFileName) return 0;
    char* filePath = JoinPath(checkDirPath, checkFileName);
    if (!filePath) return 0;
    int ret = (access(filePath, F_OK) == 0) ? 1 : 0;
    free(filePath);
    return ret;
}

// Check by full path whether password is set
int IsPasswordIsSet(const char* checkFilePath) {
    if (!checkFilePath) return 0;
    return (access(checkFilePath, F_OK) == 0) ? 1 : 0;
}


char* NotesNameToFileName(const char* notesName)
{
    size_t enc_len;
    unsigned char* enc_buf = EncryptBuffer((const unsigned char*)notesName, strlen(notesName), &enc_len);
    if (!enc_buf) {
        return NULL;
    }

    size_t b64_len = sodium_base64_encoded_len(enc_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    // +4 for ".enc" (b64_len already includes space for '\0')
    char* fileName = (char*)calloc(b64_len + 4, 1);
    if (!fileName) {
        free(enc_buf);
        return NULL;
    }

    // ✅ libsodium returns the destination pointer (fileName) or NULL on failure
    if (sodium_bin2base64(fileName, b64_len, enc_buf, enc_len,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL) {
        free(enc_buf);
        free(fileName);
        return NULL;
    }

    free(enc_buf);

    // Append extension; buffer is big enough: (b64_len includes '\0') + 4 chars + new '\0'
    strcat(fileName, ".enc");
    return fileName;
}


char* FileNameToNotesName(const char* fileName)
{
    size_t fileNameLen = strlen(fileName);
    if (fileNameLen <= 4)
        return NULL;

    size_t b64Len = fileNameLen - 4;

    char* b64Part = calloc(b64Len + 1, 1);
    if (!b64Part)
        return NULL;
    memcpy(b64Part, fileName, b64Len);
    b64Part[b64Len] = '\0';

    // Proper decoded buffer size
    size_t binDataSize = (b64Len * 3) / 4 + 3;
    unsigned char* binData = calloc(binDataSize, 1);
    if (!binData) {
        free(b64Part);
        return NULL;
    }

    size_t binLen;
    if (sodium_base642bin(
            binData, binDataSize,
            b64Part, strlen(b64Part),
            NULL, &binLen, NULL,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING
        ) != 0) // ✅ correct check
    {
        free(b64Part);
        free(binData);
        return NULL;
    }
    free(b64Part);

    size_t plain_len;
    unsigned char* plain = DecryptBuffer(binData, binLen, &plain_len);
    free(binData);

    if (!plain)
        return NULL;

    return (char*)plain; // caller frees
}

char* MakeSecureNotesZipFilename(void)
{
    uint64_t ts = (uint64_t)time(NULL);  // 64-bit timestamp
    uint32_t rnd = 0;

    randombytes_buf(&rnd, sizeof(rnd));

    char buf[80];
    int n = snprintf(buf, sizeof(buf), "MyEncryptedNotes_%llu_%u.zip",
                     (unsigned long long)ts, rnd);
    if (n < 0) return NULL;

    char* out = (char*)malloc((size_t)n + 1);
    if (!out) return NULL;

    memcpy(out, buf, (size_t)n + 1);
    return out;
}

int ImportFromZip(const char* targetDir, const char* sourceZipFilePath)
{
    if (!targetDir || !sourceZipFilePath)
        return -1;

    // Try to open zip for reading
    int err = 0;
    zip_t* za = zip_open(sourceZipFilePath, ZIP_RDONLY, &err);
    if (!za) {
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        fprintf(stderr, "Cannot open zip archive '%s': %s\n",
                sourceZipFilePath, zip_error_strerror(&error));
        zip_error_fini(&error);
        return -1;
    }

    // Create output directory if it doesn’t exist
    mkdir(targetDir);

    zip_int64_t num_entries = zip_get_num_entries(za, 0);
    for (zip_uint64_t i = 0; i < (zip_uint64_t)num_entries; i++) {
        const char* name = zip_get_name(za, i, 0);
        if (!name) {
            fprintf(stderr, "Cannot get name for entry #%llu: %s\n",
                    (unsigned long long)i, zip_strerror(za));
            continue;
        }

        // Skip directories (entries ending with '/')
        size_t nlen = strlen(name);
        if (nlen == 0 || name[nlen - 1] == '/')
            continue;

        // Read file contents from zip
        zip_file_t* zf = zip_fopen_index(za, i, 0);
        if (!zf) {
            fprintf(stderr, "Cannot open file '%s' in zip: %s\n",
                    name, zip_strerror(za));
            continue;
        }

        // Prepare output path
        char* outPath = JoinPath(targetDir, name);
        if (!outPath) {
            zip_fclose(zf);
            continue;
        }

        FILE* f = fopen(outPath, "wb");
        if (!f) {
            fprintf(stderr, "Cannot create output file '%s': %s\n",
                    outPath, strerror(errno));
            free(outPath);
            zip_fclose(zf);
            continue;
        }

        // Copy contents
        char buf[8192];
        zip_int64_t bytes_read;
        while ((bytes_read = zip_fread(zf, buf, sizeof(buf))) > 0) {
            fwrite(buf, 1, (size_t)bytes_read, f);
        }

        fclose(f);
        free(outPath);
        zip_fclose(zf);
    }

    if (zip_close(za) < 0) {
        fprintf(stderr, "Cannot close zip archive '%s': %s\n",
                sourceZipFilePath, zip_strerror(za));
        return -1;
    }

    return 0;
}

int ExportToZip(const char* sourceDir, const char* targetZipFilePath, const char* checkFileName)
{
    if (!sourceDir || !targetZipFilePath || !checkFileName)
        return -1;

    if (!IsPasswordIsSetSplitPath(sourceDir, checkFileName))
        return -1;

    int err = 0;
    zip_t* za = zip_open(targetZipFilePath, ZIP_CREATE | ZIP_EXCL, &err);
    if (!za) {
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        fprintf(stderr, "Cannot open zip archive '%s': %s\n",
                targetZipFilePath, zip_error_strerror(&error));
        zip_error_fini(&error);
        return -1;
    }

    // ---- Add verifier file ----
    char* filePath = JoinPath(sourceDir, checkFileName);
    if (!filePath) {
        zip_close(za);
        return -1;
    }

    struct zip_source* src = zip_source_file(za, filePath, 0, ZIP_LENGTH_TO_END);
    free(filePath);
    if (!src) {
        fprintf(stderr, "Cannot create source for check file '%s': %s\n",
                checkFileName, zip_strerror(za));
        zip_close(za);
        return -1;
    }

    if (zip_file_add(za, checkFileName, src, ZIP_FL_ENC_UTF_8) < 0) {
        fprintf(stderr, "Cannot add check file to zip: %s\n", zip_strerror(za));
        zip_source_free(src); // must free manually if zip_file_add fails
        zip_close(za);
        return -1;
    }

    // ---- Add all .enc files ----
    DIR* dir = opendir(sourceDir);
    if (!dir) {
        fprintf(stderr, "Could not open directory '%s': %s\n",
                sourceDir, strerror(errno));
        zip_close(za);
        return -1;
    }

    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 4 || strcmp(de->d_name + len - 4, ".enc") != 0)
            continue;

        char* encPath = JoinPath(sourceDir, de->d_name);
        if (!encPath)
            continue;

        src = zip_source_file(za, encPath, 0, ZIP_LENGTH_TO_END);
        free(encPath);
        if (!src) {
            fprintf(stderr, "Cannot create source for '%s': %s\n",
                    de->d_name, zip_strerror(za));
            closedir(dir);
            zip_close(za);
            return -1;
        }

        if (zip_file_add(za, de->d_name, src, ZIP_FL_ENC_UTF_8) < 0) {
            fprintf(stderr, "Cannot add file '%s': %s\n",
                    de->d_name, zip_strerror(za));
            zip_source_free(src);
            closedir(dir);
            zip_close(za);
            return -1;
        }
    }

    closedir(dir);

    if (zip_close(za) < 0) {
        fprintf(stderr, "Cannot close zip archive '%s': %s\n",
                targetZipFilePath, zip_strerror(za));
        return -1;
    }

    return 0;
}

int WipeAndResetStorage(const char* sourceDir, const char* checkFileName)
{
    if (!sourceDir || !checkFileName)
        return -1;

    if (!IsPasswordIsSetSplitPath(sourceDir, checkFileName))
        return -1;
        
    char* filePath = JoinPath(sourceDir, checkFileName);
    if (!filePath) {
        return -1;
    }
    
    int r = remove(filePath);
    free(filePath);
    if (r != 0)
        return -1;
        
    DIR* dir = opendir(sourceDir);
    if (!dir) {
        fprintf(stderr, "Could not open directory '%s': %s\n",
                sourceDir, strerror(errno));
        return -1;
    }
    
    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 4 || strcmp(de->d_name + len - 4, ".enc") != 0)
            continue;

        char* encPath = JoinPath(sourceDir, de->d_name);
        if (!encPath)
            continue;

        r = remove(encPath);
        free(encPath);
        if (r != 0)
        {
          closedir(dir); 
          return -1;
        }
    }

    closedir(dir);
    
    return 0;
}

