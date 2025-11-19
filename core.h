#ifndef CORE_H
#define CORE_H

#include <stddef.h> // for size_t
#include <time.h>
#include "mdlinkedlist.h"

typedef struct NoteEntry {
    long long int id;
    char* name;
} NoteEntry;

typedef struct NoteData {
    long long int id;
    char* name;
    char* userName;
    char* email;
    char* url; 
    char* password;
    char* otherSecret;
    time_t created;
    time_t modified;
} NoteData;

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define SQL_FILE "SecureStorage.sqlite"

char* JoinPath(const char* saveDirPath, const char* fileName);

// AES file encryption/decryption
int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text);
char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName);

// User password / verifier
int CheckPasswordAndDeriveEncKey(const char *password, const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSet(const char* checkFilePath);

// Initialization / cleanup
int Init();
void Logout(void);

void NotesEntry_Free(void* data);
md_linked_list_el* LoadNotesList(const char* filter);

NoteData* NoteData_New(long long int id, const char* name, const char* userName, const char* email, const char* url, const char* password, const char* otherSecret, time_t created, time_t modified);
void NoteData_Free(void* data);

int DeleteNoteData(long long int id);
NoteData* GetNoteData(long long int id);
int InsertOrUpdateNoteData(NoteData* nd);

int CalculatePasswordStrength(const char *password);
int IsPasswordSecure(const char* password);
char* GeneratePassword(void);

char* MakeZipExportFilename(void);
int ExportToZip(const char* sourceDir, const char* targetZipFilePath, const char* checkFileName, const char* dbFileName);
int ImportFromZip(const char* targetDir, const char* sourceZipFilePath);
int WipeAndResetStorage(const char* sourceDir, const char* checkFileNamem, const char* sqlFileName);
#endif // CORE_H
