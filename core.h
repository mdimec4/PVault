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

char* JoinPath(const char* saveDirPath, const char* fileName);

// AES file encryption/decryption
int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text);
char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName);

// User password / verifier
int CheckPasswordAndDeriveEncKey(const char *password, const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName);
int IsPasswordIsSet(const char* checkFilePath);

// Initialization / cleanup
int Init(const char* dataDir);
void Destroy(void);
void Logout(void);

void NotesEntry_Free(void* data);
md_linked_list_el* LoadNotesList(const char* filter);

NoteData* NoteData_New(long long int id, const char* name, const char* userName, const char* email, const char* url, const char* password, const char* otherSecret, time_t created, time_t modified);
void NoteData_Free(void* data);
NoteData* GetNoteData(long long int id);

char* NotesNameToFileName(const char* notesName);
char* FileNameToNotesName(const char* fileName);

char* MakeJsonExportFilename(void);
int WipeAndResetStorage(const char* sourceDir, const char* checkFileName);
#endif // CORE_H
