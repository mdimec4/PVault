#ifndef CORE_H
#define CORE_H

#include <stddef.h> // for size_t

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

char* JoinPath(const char* saveDirPath, const char* fileName);

// AES file encryption/decryption
int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text);
char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName);

// User password / verifier
int CheckPasswordAndDeriveEncKey(const char *password, const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSet(const char* checkFilePath);

// Initialization / cleanup
int Init(void);
void Logout(void);

char* NotesNameToFileName(const char* notesName);
char* FileNameToNotesName(const char* fileName);

char* MakeSecureNotesZipFilename(void);
int ExportToZip(const char* sourceDir, const char* targetZipFilePath, const char* checkFileName);
int ImportFromZip(const char* targetDir, const char* sourceZipFilePath);
int WipeAndResetStorage(const char* sourceDir, const char* checkFileName);
#endif // CORE_H
