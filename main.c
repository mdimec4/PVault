#define _UNICODE
#include <windows.h>
#include <richedit.h>
#include <commdlg.h>
#include <shlobj.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "core.h"
#include "mdlinkedlist.h"
#include "resource.h"
#include "modern_ui.h"

#ifdef _MSC_VER
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
  name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
  processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#define AUTOSAVE_TIMER_ID 42
#define AUTOSAVE_DELAY_MS 2000

#define INACTIVITY_TIMER_ID 99
#define INACTIVITY_TIMEOUT_MS (5 * 60 * 1000) // 5 minutes

#define COLOR_LOGIN_BG RGB(245, 247, 250)
#define COLOR_EDITOR_BG RGB(250, 250, 250)

// Consistent UI layout
const int MARGIN = 20;
const int SPACING = 10;
const int BUTTON_HEIGHT = 32;
const int BUTTON_WIDTH = 140;
const int CONTROL_SPACING = 10;

HWND hTitleLabel;
HBRUSH gBrushBackground;


typedef struct NoteEntry {
    wchar_t name[256];
    char* fileName;  // malloc'ed
} NoteEntry;

struct FileEntry {
    char fileName[MAX_PATH];
    FILETIME ftLastWrite;
};

static wchar_t gDataDirW[MAX_PATH] = {0};
static char    gDataDirA[MAX_PATH] = {0};

static md_linked_list_el* gNotes = NULL;
static NoteEntry* gCurrentNote = NULL;
static UINT_PTR gAutoSaveTimer = 0;
static BOOL gTextChanged = FALSE;

HWND hPasswordLabel, hPasswordEdit, hPasswordEdit2, hUnlockButton, hWipeButton, hImportButton;
HWND hStrengthBar, hHintLabel;
HWND hEdit, hLogoutButton;
HFONT hFont, hFontEdit;
BOOL isUnlocked = FALSE;
static BOOL gShowingLogoutMsg = FALSE;
static BOOL gInLogout = FALSE;

HWND hNotesList, hNewNoteButton, hDeleteNoteButton;
const int listWidth = 200;

HWND hExportButton;
HFONT hTitleFont = NULL;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void ShowLoginUI(HWND hwnd);
void ShowEditorUI(HWND hwnd);
void DestroyLoginUI(void);
void DestroyEditorUI(HWND hwnd);
void LoadAndDecryptText(HWND hEdit);
void SaveEncryptedText(HWND hEdit);
static int CalculatePasswordStrength(const char *password);

static void NotesEntry_Free(void* data)
{
    if (!data)
        return;
    NoteEntry* ne = (NoteEntry*)data;
    SecureZeroMemory(ne->fileName, strlen(ne->fileName));
    SecureZeroMemory(ne->name, sizeof(ne->name));
    free(ne->fileName);
    free(data);
}

static void NotesList_FreeAll(void)
{
    if (!gNotes)
        return;
    md_linked_list_free_all(gNotes, NotesEntry_Free);
    gNotes = NULL;
}

static int CompareFileEntry(const void* a, const void* b)
{
    const struct FileEntry* fa = (const struct FileEntry*)a;
    const struct FileEntry* fb = (const struct FileEntry*)b;
    return CompareFileTime(&fb->ftLastWrite, &fa->ftLastWrite);
}

static void NotesList_LoadFromDir(HWND hNotesList)
{
    WIN32_FIND_DATAA fd;
    
    char* searchPath = JoinPath(gDataDirA, "*.enc");
    if (!searchPath) return;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    free(searchPath);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    struct FileEntry files[512];
    int fileCount = 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            memcpy(files[fileCount].fileName, fd.cFileName, MAX_PATH - 1);
            files[fileCount].fileName[MAX_PATH - 1] = 0;
            files[fileCount].ftLastWrite = fd.ftLastWriteTime;
            fileCount++;
        }
    } while (FindNextFileA(hFind, &fd) && fileCount < 512);

    FindClose(hFind);

    /* Sort by modification time, newest first */
    qsort(files, fileCount, sizeof(files[0]), CompareFileEntry);

    NotesList_FreeAll();
    SendMessageW(hNotesList, LB_RESETCONTENT, 0, 0);

    for (int i = 0; i < fileCount; i++) {
        char* noteNameUtf8 = FileNameToNotesName(files[i].fileName);
        if (!noteNameUtf8)
            continue;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, noteNameUtf8, -1, NULL, 0);
        if (wlen <= 0) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            continue;
        }

        wchar_t* wname = (wchar_t*)malloc(wlen * sizeof(wchar_t));
        if (!wname) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            continue;
        }

        MultiByteToWideChar(CP_UTF8, 0, noteNameUtf8, -1, wname, wlen);

        NoteEntry* n = (NoteEntry*)calloc(1, sizeof(NoteEntry));
        if (!n) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            free(wname);
            continue;
        }

        wcscpy_s(n->name, 256, wname);
        n->fileName = _strdup(files[i].fileName);
        
        gNotes = md_linked_list_add(gNotes, n);

        int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)n->name);
        SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)n);

        SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
        free(noteNameUtf8);
        free(wname);
    }
}

void InitStoragePath(void)
{
    // Get %LOCALAPPDATA%
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, gDataDirW)))
    {
        wcscat_s(gDataDirW, MAX_PATH, L"\\MySecureNote");
        CreateDirectoryW(gDataDirW, NULL);

        // Convert UTF-16 → UTF-8 once
        WideCharToMultiByte(CP_UTF8, 0, gDataDirW, -1, gDataDirA, sizeof(gDataDirA), NULL, NULL);
    }
    else
    {
        // fallback to current directory
        wcscpy_s(gDataDirW, MAX_PATH, L".");
        strcpy_s(gDataDirA, sizeof(gDataDirA), ".\\");
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    LoadLibrary(TEXT("Msftedit.dll"));
    
    InitStoragePath();
    if (Init() != 0) {
        MessageBox(NULL, L"Failed to initialize Secure Notes (libsodium error).", L"Fatal Error", MB_ICONERROR);
        return 1;
    }
    
    const wchar_t CLASS_NAME[] = L"MyEncryptedNotesWindow";

    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    // Set both large and small icons
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    wc.hIconSm = (HICON)LoadImage(
        hInstance,
        MAKEINTRESOURCE(IDI_APP_ICON),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        0);

    RegisterClassEx(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"MyEncryptedNotes",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 2048, 1024,
        NULL, NULL, hInstance, NULL);

    if (!hwnd)
        return 0;
        
    // DWM_WINDOW_CORNER_PREFERENCE preference = DWMWCP_ROUND;
    // DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE,
    //                  &preference, sizeof(preference));
    // BOOL val = TRUE;
    // DwmSetWindowAttribute(hwnd, DWMWA_NCRENDERING_POLICY, &val, sizeof(val));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

static void WipeWindowText(HWND wnd)
{
    if (!wnd || !IsWindow(wnd)) 
        return;
        
    int len = GetWindowTextLengthW(wnd);
    if (len > 0) {
        wchar_t* buf = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
        if (buf) {
            GetWindowTextW(wnd, buf, len + 1);
            SecureZeroMemory(buf, (len + 1) * sizeof(wchar_t));
            free(buf);
        }
    }
    SetWindowTextW(wnd, L"");
}

static void StartOrBumpInactivityTimer(HWND hwnd)
{
    // For window timers, SetTimer with same (hwnd,id) replaces existing one — no KillTimer needed.
    SetTimer(hwnd, INACTIVITY_TIMER_ID, INACTIVITY_TIMEOUT_MS, NULL);
}

static void ResetInactivityTimer(HWND hwnd)
{
    StartOrBumpInactivityTimer(hwnd);
}

static void StopInactivityTimer(HWND hwnd)
{
    KillTimer(hwnd, INACTIVITY_TIMER_ID);
}

static void PerformLogout(HWND hwnd, BOOL autoLogout)
{
    
    if (gInLogout) return;
    gInLogout = TRUE;
    
    StopInactivityTimer(hwnd);
    
    if (gCurrentNote && gTextChanged)
    {
        SaveEncryptedText(hEdit);
        gTextChanged = FALSE;
    }

    DestroyEditorUI(hwnd);
    Logout();
    isUnlocked = FALSE;
    ShowLoginUI(hwnd);
    
    if (autoLogout && !gShowingLogoutMsg)
    {
        gShowingLogoutMsg = TRUE;
        SetForegroundWindow(hwnd);
        MessageBox(hwnd, L"You have been logged out due to inactivity.", L"Session Timeout", MB_ICONINFORMATION);
        gShowingLogoutMsg = FALSE;
    }
    
    gInLogout = FALSE;
}

INT_PTR CALLBACK NewNoteDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
        // Save pointer to user buffer (passed via lParam)
        SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t* nameBuf = (wchar_t*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
            if (nameBuf) {
                GetDlgItemTextW(hDlg, 1000, nameBuf, 255);
            }
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// helper to move a control and clean old area
static void MoveControl(HWND parent, HWND ctrl, int x, int y, int w, int h) {
    if (!ctrl || !IsWindow(ctrl)) return;
    
    RECT old; GetWindowRect(ctrl, &old);
    MapWindowPoints(NULL, parent, (POINT*)&old, 2); // to parent coords
    MoveWindow(ctrl, x, y, w, h, TRUE);
    InvalidateRect(parent, &old, TRUE); // erase where it used to be
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);
        InitModernUI(hwnd);
        hFont = CreateModernUIFont(16, FALSE);
        ShowLoginUI(hwnd);
        return 0;
    }

    case WM_COMMAND:
       if (LOWORD(wParam) == 1001) // Unlock
       {
            int len = GetWindowTextLengthW(hPasswordEdit) + 1;
            wchar_t* pwbuf = (wchar_t*)malloc(len * sizeof(wchar_t));
            GetWindowTextW(hPasswordEdit, pwbuf, len);

            int buflen = WideCharToMultiByte(CP_UTF8, 0, pwbuf, -1, NULL, 0, NULL, NULL);
            char* password = (char*)malloc(buflen);
            WideCharToMultiByte(CP_UTF8, 0, pwbuf, -1, password, buflen, NULL, NULL);

             // Clear the password field immediately after copying
             WipeWindowText(hPasswordEdit);
             
             if (hPasswordEdit2 != NULL)
             {             
                if (strlen(password) < 12 || 
                    !strpbrk(password, "abcdefghijklmnopqrstuvwxyz") ||
                    !strpbrk(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
                    !strpbrk(password, "0123456789") ||
                    !strpbrk(password, "!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~")) 
                {
                    WipeWindowText(hPasswordEdit2);
                     
                     // Securely wipe password buffers
                     SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
                     SecureZeroMemory(password, buflen);

                     free(pwbuf);
                     free(password);
                     
                    MessageBox(hwnd,
                        L"Password must be at least 12 characters long and include upper/lowercase letters, digits, and symbols.",
                        L"Invalid Password", MB_ICONERROR);
                    return 0;
                }
                int len2 = GetWindowTextLengthW(hPasswordEdit2) + 1;
                wchar_t* pwbuf2 = (wchar_t*)malloc(len2 * sizeof(wchar_t));
                GetWindowTextW(hPasswordEdit2, pwbuf2, len2);

                int buflen2 = WideCharToMultiByte(CP_UTF8, 0, pwbuf2, -1, NULL, 0, NULL, NULL);
                char* password2 = (char*)malloc(buflen2);
                WideCharToMultiByte(CP_UTF8, 0, pwbuf2, -1, password2, buflen2, NULL, NULL);
                
                // Clear the password field immediately after copying
                WipeWindowText(hPasswordEdit2);
                
                if (buflen != buflen2 || strncmp(password, password2, MIN(buflen, buflen2)) != 0)
                {
                    MessageBox(hwnd, L"Passwords don't match!", L"Error", MB_ICONERROR);
                    
                    SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
                    SecureZeroMemory(password, buflen);
                    SecureZeroMemory(pwbuf2, len2 * sizeof(wchar_t));
                    SecureZeroMemory(password2, buflen2);

                    free(pwbuf);
                    free(password);
                    free(pwbuf2);
                    free(password2);
                    return 0;
                }
                
                // Securely wipe password buffers
                SecureZeroMemory(pwbuf2, len * sizeof(wchar_t));
                SecureZeroMemory(password2, buflen2);

                free(pwbuf2);
                free(password2);
            }

             int success = CheckPasswordAndDeriveEncKey(password, gDataDirA, "verifier.dat");

             // Securely wipe password buffers
             SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
             SecureZeroMemory(password, buflen);

             free(pwbuf);
             free(password);

             if (success)
             {
                 isUnlocked = TRUE;
                 DestroyLoginUI();
                 ShowEditorUI(hwnd);
                 ResetInactivityTimer(hwnd);
             }
             else
             {
                 MessageBox(hwnd, L"Wrong password or failed to derive AES key.", L"Error", MB_ICONERROR);
             }

             return 0;
        }
        else if (LOWORD(wParam) == 1002) // Wipe storage
        {
            int result = MessageBoxW(
                hwnd,
                L"Are you sure you want to wipe your existing notes storage? All notes will be permanently lost!",
                L"Confirm Storage Wipe",
                MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2
            );
            if (result != IDYES)
                return 0;
                
            if (WipeAndResetStorage(gDataDirA, "verifier.dat") != 0)
            {
                MessageBox(hwnd, L"Failed to wipe existing data.", L"Error", MB_ICONERROR);
                return 0;
            }
            DestroyLoginUI();
            ShowLoginUI(hwnd);
                
            return 0;
        }
        else if (LOWORD(wParam) == 1003) // Manual Logout
        {
            PerformLogout(hwnd, FALSE);
            return 0;
        }
         else if (LOWORD(wParam) == 1004) // Import storage
        {
            OPENFILENAMEW ofn = {0};
            wchar_t szFile[260] = L"";

            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = sizeof(szFile);
            ofn.lpstrFilter = L"Zip Files (*.zip)\0*.zip\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

            if (GetOpenFileNameW(&ofn)) {
                char pathUtf8[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, pathUtf8, sizeof(pathUtf8), NULL, NULL);
                if (ImportFromZip(gDataDirA, pathUtf8) != 0)
                {
                    MessageBox(hwnd, L"Failed to import data.", L"Error", MB_ICONERROR);
                    return 0;
                }
                MessageBoxW(hwnd, L"Import complete!", L"Success", MB_ICONINFORMATION);
                DestroyLoginUI();
                ShowLoginUI(hwnd);
            }

            return 0;
        }
        else if (LOWORD(wParam) == 3000 && HIWORD(wParam) == LBN_SELCHANGE) {
            // Auto-save current note before switching
            if (gCurrentNote && gTextChanged) {
                SaveEncryptedText(hEdit);
                gTextChanged = FALSE;
            }

            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                SaveEncryptedText(hEdit);
                gCurrentNote = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
                if (gCurrentNote) {
                    LoadAndDecryptText(hEdit);
                    gTextChanged = FALSE;
                    EnableWindow(hEdit, TRUE);
                }
            }
        }
        else if (LOWORD(wParam) == 3001) { // New Note
            wchar_t wNewName[256] = L"";
            if (DialogBoxParamW(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_NEW_NOTE), hwnd, NewNoteDialogProc, (LPARAM)wNewName) == IDOK) {
                if (wcslen(wNewName) == 0) {
                    MessageBox(hwnd, L"Note name cannot be empty.", L"Error", MB_ICONERROR);
                    return 0;
                }

                // Check duplicates
                for (md_linked_list_el* el = gNotes; el; el = el->next) {
                    NoteEntry* ne = (NoteEntry*)el->data;
                    if (_wcsicmp(ne->name, wNewName) == 0) {
                        MessageBox(hwnd, L"Note already exists.", L"Error", MB_ICONERROR);
                        return 0;
                    }
                }

                char noteNameUtf8[256];
                WideCharToMultiByte(CP_UTF8, 0, wNewName, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);
                char* fileName = NotesNameToFileName(noteNameUtf8);
                if (!fileName) {
                    MessageBox(hwnd, L"Failed to create filename.", L"Error", MB_ICONERROR);
                    return 0;
                }

                // Create note entry
                NoteEntry* n = calloc(1, sizeof(NoteEntry));
                wcscpy_s(n->name, 256, wNewName);
                n->fileName = fileName;
               
               // prepend to linked list
               md_linked_list_el* new_el = calloc(1, sizeof(md_linked_list_el));
               new_el->prev = NULL;
               new_el->next = gNotes;
               new_el->data = n;
               if(gNotes)
                   gNotes->prev = new_el;
               gNotes = new_el;

                // re-populate notes list
                SendMessageW(hNotesList, LB_RESETCONTENT, 0, 0);
                BOOL isNewElement = TRUE;
                for(md_linked_list_el* el = gNotes; el; el = el->next){
                    NoteEntry* ne = (NoteEntry*)el->data;
                    
                    int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)ne->name);
                    SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)ne);
                    if (isNewElement)
                    {
                        SendMessageW(hNotesList, LB_SETCURSEL, idx, 0);
                        isNewElement = FALSE;
                    }
                }
                    
                gCurrentNote = n;
                SetWindowTextW(hEdit, L"");
                EnableWindow(hEdit, TRUE);
                gTextChanged = FALSE;
                EncryptAndSaveFile(gDataDirA, gCurrentNote->fileName, "");
            }
        }
        else if (LOWORD(wParam) == 3002) { // Delete
            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR) return 0;

            NoteEntry* n = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
            if (!n) return 0;

            char* path = JoinPath(gDataDirA, n->fileName);
            if (!path) return 0;
            DeleteFileA(path);
            free(path);
            
            SendMessage(hNotesList, LB_DELETESTRING, sel, 0);

            // Remove from linked list
            md_linked_list_el* remove_el = gNotes;
            while(remove_el && remove_el->data != n) remove_el = remove_el-> next;
            if (remove_el)
                gNotes = md_linked_list_remove(gNotes, remove_el, NotesEntry_Free);

            gCurrentNote = NULL;
            WipeWindowText(hEdit);
            EnableWindow(hEdit, FALSE);
        }
        else if (LOWORD(wParam) == 3003) { // EXPORT
            char* suggestedName = MakeSecureNotesZipFilename();

            // Convert UTF-8 → UTF-16 for Windows dialog
            wchar_t wSuggested[260];
            MultiByteToWideChar(CP_UTF8, 0, suggestedName, -1, wSuggested, 260);
            free(suggestedName);

            OPENFILENAMEW ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = wSuggested;
            ofn.nMaxFile = ARRAYSIZE(wSuggested);
            ofn.lpstrFilter = L"Zip Files (*.zip)\0*.zip\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

            if (GetSaveFileNameW(&ofn)) {
                // Convert chosen path back to UTF-8 for your core ExportToZip()
                char targetPath[512];
                WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, targetPath, sizeof(targetPath), NULL, NULL);

                if (ExportToZip(gDataDirA, targetPath, "verifier.dat") != 0)
                {
                     MessageBox(hwnd, L"Failed to export data.", L"Error", MB_ICONERROR);
                     return 0;
                }
                MessageBoxW(hwnd, L"Export complete!", L"Success", MB_ICONINFORMATION);
            }
        }
        else if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == hEdit) {
            gTextChanged = TRUE;
            ResetInactivityTimer(hwnd); // <--- reset timer on text change

            if (gAutoSaveTimer)
                KillTimer(hwnd, AUTOSAVE_TIMER_ID);  // use thread timer

            gAutoSaveTimer = SetTimer(
                hwnd,
                AUTOSAVE_TIMER_ID,
                AUTOSAVE_DELAY_MS,
                NULL
            );
        }
        else if ((HWND)lParam == hPasswordEdit && HIWORD(wParam) == EN_CHANGE)
        {
            if (!hStrengthBar) return 0;
            
            int len = GetWindowTextLengthW(hPasswordEdit) + 1;
            wchar_t* wbuf = malloc(len * sizeof(wchar_t));
            GetWindowTextW(hPasswordEdit, wbuf, len);

            int utf8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
            char* passUtf8 = malloc(utf8len);
            WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, passUtf8, utf8len, NULL, NULL);

            int strength = CalculatePasswordStrength(passUtf8);

            // Update visual meter
            int progress = (strength * 100) / 7;
            SendMessage(hStrengthBar, PBM_SETPOS, progress, 0);

            // Change color dynamically
            COLORREF color;
            if (strength <= 2) color = RGB(255, 60, 60);     // weak (red)
            else if (strength <= 4) color = RGB(255, 200, 0); // medium (yellow)
            else color = RGB(0, 200, 0);                      // strong (green)
            SendMessage(hStrengthBar, PBM_SETBARCOLOR, 0, (LPARAM)color);

            SecureZeroMemory(wbuf, len * sizeof(wchar_t));
            SecureZeroMemory(passUtf8, utf8len);
            free(wbuf);
            free(passUtf8);
        }
        break;
    case WM_TIMER:
        if (wParam == AUTOSAVE_TIMER_ID) {
            KillTimer(hwnd, AUTOSAVE_TIMER_ID);
            gAutoSaveTimer = 0;
            if (gTextChanged && gCurrentNote) {
                SaveEncryptedText(hEdit);
                gTextChanged = FALSE;
            }
        }
        else if (wParam == INACTIVITY_TIMER_ID)
        {
            StopInactivityTimer(hwnd);    // ensure it can’t re-fire
            PerformLogout(hwnd, TRUE);
        }
        break;
    case WM_MOUSEMOVE:
        if (isUnlocked) {
            static int lastX = -1, lastY = -1;
            int x = LOWORD(lParam), y = HIWORD(lParam);
            if (x != lastX || y != lastY) {
                ResetInactivityTimer(hwnd);
                lastX = x; lastY = y;
            }
        }
    break;
    case WM_KEYDOWN:
        if (isUnlocked)
            ResetInactivityTimer(hwnd);
        break;
    case WM_CTLCOLORSTATIC:
    {
        static HBRUSH hBrushStatic = NULL;
        COLORREF bg = isUnlocked ? COLOR_EDITOR_BG : COLOR_LOGIN_BG;

        if (hBrushStatic)
            DeleteObject(hBrushStatic);
        hBrushStatic = CreateSolidBrush(bg);

        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(32, 32, 32));
        return (INT_PTR)hBrushStatic;
    }
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(32,32,32));   // darker gray text
        return (INT_PTR)gBrushBackground;
    }
    case WM_ERASEBKGND:
        PaintModernBackground(hwnd, (HDC)wParam, FALSE, CLR_INVALID);
        return 1;
    case WM_DRAWITEM:
        if (ModernUI_HandleDrawItem(lParam)) return TRUE;
            break;
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (isUnlocked)
        {       
            
            int buttonHalfWidth = (listWidth - 3 * CONTROL_SPACING) / 2;

            // consistent vertical spacing between controls and edges
            int buttonY = rc.bottom - MARGIN - BUTTON_HEIGHT;  

            // Calculate usable height for list above buttons
            int listHeight = buttonY - MARGIN - CONTROL_SPACING;   
            
            MoveWindow(hNotesList,MARGIN, MARGIN,
                   listWidth - MARGIN, listHeight, TRUE);
            MoveWindow(hNewNoteButton,  MARGIN,
                   buttonY, buttonHalfWidth, BUTTON_HEIGHT, TRUE);
            MoveWindow(hDeleteNoteButton,  MARGIN + buttonHalfWidth + CONTROL_SPACING,
                   buttonY, buttonHalfWidth, BUTTON_HEIGHT, TRUE);
            MoveWindow(hEdit, listWidth + MARGIN, MARGIN,
                   rc.right - listWidth - 2 * MARGIN,
                   listHeight, TRUE);
            MoveWindow(hExportButton, rc.right - 2 * MARGIN - BUTTON_WIDTH * 2 - CONTROL_SPACING,
                   buttonY, BUTTON_WIDTH, BUTTON_HEIGHT, TRUE);
            MoveWindow(hLogoutButton,  rc.right - MARGIN - BUTTON_WIDTH,
                   buttonY, BUTTON_WIDTH, BUTTON_HEIGHT, TRUE);
        }
        else
        {

            const int centerX = rc.right / 2;
            const int centerY = rc.bottom / 2;
            const int editWidth = 300;
            const int editHeight = 28;
            const int spacing = 10;
                
            MoveWindow(hTitleLabel, centerX - 150, centerY - 160, 300, 40, TRUE);
            MoveWindow(hPasswordLabel, centerX - editWidth/2, centerY - 80, editWidth, 24, TRUE);
            MoveWindow(hPasswordEdit, centerX - editWidth/2, centerY - 50, editWidth, editHeight, TRUE);
            if (hPasswordEdit2 != NULL)
                MoveWindow(hPasswordEdit2, centerX - editWidth/2, centerY - 50 + editHeight + spacing, editWidth, editHeight, TRUE);
                
             int strengthY = centerY - 50 + editHeight * 2 + spacing * 2;
            if  (hStrengthBar != NULL)
            {
                MoveWindow(hStrengthBar,  centerX - editWidth/2, strengthY, editWidth, 12, TRUE);
            }
            if (hHintLabel != NULL)
                MoveWindow(hHintLabel, centerX - editWidth/2, strengthY + 16, editWidth, 90, TRUE);
                
            MoveControl(hwnd, hUnlockButton,
                centerX - BUTTON_WIDTH/2,
                (hStrengthBar ? (strengthY + 16 + 70) : (centerY + 10)),
                BUTTON_WIDTH, BUTTON_HEIGHT);
            
            if (hWipeButton != NULL)
                MoveWindow(hWipeButton, rc.right - MARGIN - BUTTON_WIDTH, rc.bottom - MARGIN - BUTTON_HEIGHT, BUTTON_WIDTH, BUTTON_HEIGHT, TRUE);
            if (hImportButton != NULL)
                MoveWindow(hImportButton, rc.right - MARGIN - BUTTON_WIDTH, rc.bottom - MARGIN - BUTTON_HEIGHT, BUTTON_WIDTH, BUTTON_HEIGHT, TRUE);

        }
        RedrawWindow(hwnd, NULL, NULL,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
        return 0;
    }

    case WM_DESTROY: {
        if (gCurrentNote && gTextChanged)
        {
            SaveEncryptedText(hEdit);
            gTextChanged = FALSE;
        }
        NotesList_FreeAll();
        
        if (hEdit && IsWindow(hEdit)) {
            WipeWindowText(hEdit);
            DestroyWindow(hEdit);
        }
        
        if (gBrushBackground)
        {
            DeleteObject(gBrushBackground);
            gBrushBackground = NULL;
        }
        
        Logout();
        DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void ShowLoginUI(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    
    BOOL isPasswordSet = IsPasswordIsSetSplitPath(gDataDirA, "verifier.dat");
    
    const int centerX = rc.right / 2;
    const int centerY = rc.bottom / 2;
    const int editWidth = 300;
    const int editHeight = 28;
    const int spacing = 10;

    hTitleLabel = CreateWindow(L"static", L"MyEncryptedNotes",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        centerX - 150, centerY - 160, 300, 40,
        hwnd, NULL, NULL, NULL);

    LOGFONT titleFont;
    GetObject(hFont, sizeof(LOGFONT), &titleFont);
    titleFont.lfHeight = -24;
    hTitleFont = CreateFontIndirect(&titleFont);
    SendMessage(hTitleLabel, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // password label
    hPasswordLabel = CreateWindow(L"static", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        centerX - editWidth/2, centerY - 80, editWidth, 24,
        hwnd, (HMENU)501, NULL, NULL);
    SetWindowText(hPasswordLabel, isPasswordSet ? L"Password:" : L"New password:");
    SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // first password box
    hPasswordEdit = CreateWindowEx(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
        centerX - editWidth/2, centerY - 50, editWidth, editHeight,
        hwnd, (HMENU)1000, NULL, NULL);
    SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    if (!isPasswordSet)
    {
        // confirm password
        hPasswordEdit2 = CreateWindowEx(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
            centerX - editWidth/2, centerY - 50 + editHeight + spacing,
            editWidth, editHeight,
            hwnd, (HMENU)1123, NULL, NULL);
        SendMessage(hPasswordEdit2, WM_SETFONT, (WPARAM)hFont, TRUE);

        //
        // Strength bar (below password fields)
        //
        int strengthY = centerY - 50 + editHeight * 2 + spacing * 2;

        hStrengthBar = CreateWindowEx(0, PROGRESS_CLASS, NULL,
            WS_CHILD | WS_VISIBLE,
            centerX - editWidth/2, strengthY, editWidth, 12,
            hwnd, (HMENU)2001, GetModuleHandle(NULL), NULL);
        SendMessage(hStrengthBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hStrengthBar, PBM_SETPOS, 0, 0);

        // hint label
        hHintLabel = CreateWindowEx(0, L"STATIC",
            L"Use at least 12 characters, including upper/lowercase, digits, and special characters.",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            centerX - editWidth/2, strengthY + 16, editWidth, 90,
            hwnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessage(hHintLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Set password button
        hUnlockButton = CreateWindow(
            L"BUTTON", L"Set password",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            centerX - BUTTON_WIDTH / 2, strengthY + 16 + 70, BUTTON_WIDTH, BUTTON_HEIGHT,
            hwnd, (HMENU)1001, NULL, NULL);
        ApplyModernButton(hUnlockButton);
        SendMessage(hUnlockButton, WM_SETFONT, (WPARAM)hFont, TRUE);

        hWipeButton = NULL;
        hImportButton = CreateWindow(
            L"BUTTON", L"Import storage",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rc.right - MARGIN - BUTTON_WIDTH, rc.bottom - MARGIN - BUTTON_HEIGHT, BUTTON_WIDTH, BUTTON_HEIGHT,
            hwnd, (HMENU)1004, NULL, NULL);
        ApplyModernButton(hImportButton);
        SendMessage(hImportButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    else
    {
        hPasswordEdit2 = NULL;
        hStrengthBar = NULL;
        hHintLabel = NULL;

        // Unlock button (centered below password)
        hUnlockButton = CreateWindow(
            L"BUTTON", L"Unlock",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            centerX - BUTTON_WIDTH / 2, centerY + 10, BUTTON_WIDTH, BUTTON_HEIGHT,
            hwnd, (HMENU)1001, NULL, NULL);
        ApplyModernButton(hUnlockButton);
        SendMessage(hUnlockButton, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Wipe storage button in bottom-right corner
        hWipeButton = CreateWindow(
            L"BUTTON", L"Wipe storage",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rc.right - MARGIN - BUTTON_WIDTH, rc.bottom - MARGIN - BUTTON_HEIGHT,
            BUTTON_WIDTH, BUTTON_HEIGHT,
            hwnd, (HMENU)1002, NULL, NULL);
        ApplyModernButton(hWipeButton);
        SendMessage(hWipeButton, WM_SETFONT, (WPARAM)hFont, TRUE);
        hImportButton = NULL;
    }
}


void DestroyLoginUI(void)
{
    if (hTitleLabel && IsWindow(hTitleLabel)) {
        DestroyWindow(hTitleLabel);
        if (hTitleFont) {
            DeleteObject(hTitleFont);
            hTitleFont = NULL;
        }
        hTitleLabel = NULL;
    }
    if (hPasswordLabel && IsWindow(hPasswordLabel)) DestroyWindow(hPasswordLabel);
    if (hPasswordEdit && IsWindow(hPasswordEdit)) DestroyWindow(hPasswordEdit);
    if (hPasswordEdit2 && IsWindow(hPasswordEdit2)) DestroyWindow(hPasswordEdit2);
    if (hStrengthBar && IsWindow(hStrengthBar)) DestroyWindow(hStrengthBar);
    if (hHintLabel && IsWindow(hHintLabel)) DestroyWindow(hHintLabel);
    if (hWipeButton && IsWindow(hWipeButton)) DestroyWindow(hWipeButton);
    if (hImportButton && IsWindow(hImportButton)) DestroyWindow(hImportButton);
    if (hUnlockButton && IsWindow(hUnlockButton)) DestroyWindow(hUnlockButton);
}

void ShowEditorUI(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    
    int buttonHalfWidth = (listWidth - 3 * CONTROL_SPACING) / 2;

    // consistent vertical spacing between controls and edges
    int buttonY = rc.bottom - MARGIN - BUTTON_HEIGHT;  

    // Calculate usable height for list above buttons
    int listHeight = buttonY - MARGIN - CONTROL_SPACING;

 

    // Notes list on the left
    hNotesList = CreateWindowEx(
        0, L"LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_VSCROLL,
        MARGIN, MARGIN, listWidth - MARGIN, listHeight,
        hwnd, (HMENU)3000, NULL, NULL);
    SetWindowTheme(hNotesList, L"", L"");
        
    hNewNoteButton = CreateWindow(
        L"BUTTON", L"New Note",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN, buttonY, buttonHalfWidth, BUTTON_HEIGHT,
        hwnd, (HMENU)3001, NULL, NULL);
    ApplyModernButton(hNewNoteButton);

    hDeleteNoteButton = CreateWindow(
        L"BUTTON", L"Delete",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
         MARGIN + buttonHalfWidth + CONTROL_SPACING, buttonY, buttonHalfWidth, BUTTON_HEIGHT,
        hwnd, (HMENU)3002, NULL, NULL);
    ApplyModernButton(hDeleteNoteButton);

    // Rich Edit for note text
    hEdit = CreateWindowEx(
        0, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        listWidth + MARGIN, MARGIN, rc.right - listWidth - 2 * MARGIN, listHeight,
        hwnd, (HMENU)2000, NULL, NULL);
    SetWindowTheme(hEdit, L"", L"");
    
    LOGFONT editFont;
    GetObject(hFont, sizeof(LOGFONT), &editFont);
    editFont.lfHeight = -20;
    hFontEdit = CreateFontIndirect(&editFont);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFontEdit, TRUE);
        
    // Subscribe to EN_CHANGE notifications
    SendMessage(hEdit, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    
    NotesList_LoadFromDir(hNotesList);
    
    EnableWindow(hEdit, FALSE);

    // Bottom-right buttons
    hExportButton = CreateWindow(
        L"BUTTON", L"Export storage",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 2 * MARGIN - BUTTON_WIDTH * 2 - CONTROL_SPACING, buttonY, BUTTON_WIDTH, BUTTON_HEIGHT, 
        hwnd, (HMENU)3003, NULL, NULL);
    ApplyModernButton(hExportButton);

    hLogoutButton = CreateWindow(
        L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
         rc.right - MARGIN - BUTTON_WIDTH, buttonY, BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)1003, NULL, NULL);
    ApplyModernButton(hLogoutButton);

    SendMessage(hNotesList, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNewNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hDeleteNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hExportButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLogoutButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    int count = (int)SendMessage(hNotesList, LB_GETCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, L"No notes found. Please create a new note to begin.", L"Welcome", MB_ICONINFORMATION);
    }
}

void DestroyEditorUI(HWND hwnd)
{
    // Stop any pending autosave timer
    if (gAutoSaveTimer) {
        KillTimer(hwnd, AUTOSAVE_TIMER_ID);
        gAutoSaveTimer = 0;
    }
    
    StopInactivityTimer(hwnd);

    // Securely clear text before destroying the editor control
    if (hEdit && IsWindow(hEdit)) {
        WipeWindowText(hEdit);
        DestroyWindow(hEdit);
        hEdit = NULL;
        if (hFontEdit)
        {
            DeleteObject(hFontEdit);
            hFontEdit = NULL;
        }
    }

    // Destroy all remaining editor UI elements
    if (hLogoutButton && IsWindow(hLogoutButton)) {
        DestroyWindow(hLogoutButton);
        hLogoutButton = NULL;
    }

    if (hNotesList && IsWindow(hNotesList)) {
        DestroyWindow(hNotesList);
        hNotesList = NULL;
    }

    if (hNewNoteButton && IsWindow(hNewNoteButton)) {
        DestroyWindow(hNewNoteButton);
        hNewNoteButton = NULL;
    }
    
    if (hDeleteNoteButton && IsWindow(hDeleteNoteButton)) {
        DestroyWindow(hDeleteNoteButton);
        hDeleteNoteButton = NULL;
    }
    
    if (hExportButton && IsWindow(hExportButton)) {
        DestroyWindow(hExportButton);
        hExportButton = NULL;
    }

    NotesList_FreeAll();
    
    // Reset globals
    gCurrentNote = NULL;
    gTextChanged = FALSE;
}

void LoadAndDecryptText(HWND hEdit)
{
    if (!gCurrentNote || !gCurrentNote->fileName || !*gCurrentNote->fileName) {
        SetWindowTextW(hEdit, L"");
        return;
    }

    char* text = ReadFileAndDecrypt(gDataDirA, gCurrentNote->fileName);
    if (!text) {
        SetWindowTextW(hEdit, L"");
        return;
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, wlen);
    SetWindowTextW(hEdit, wtext);

    SecureZeroMemory(text, strlen(text));
    free(text);
    free(wtext);
}

void SaveEncryptedText(HWND hEdit)
{
    if (!gCurrentNote || !gCurrentNote->fileName || !*gCurrentNote->fileName)
        return;

    int wlen = GetWindowTextLengthW(hEdit);
    if (wlen < 0) return;

    wchar_t* wtext = malloc((wlen + 1) * sizeof(wchar_t));
    if (!wtext) return;
    GetWindowTextW(hEdit, wtext, wlen + 1);

    int buflen = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    char* text = malloc(buflen);
    if (!text) { free(wtext); return; }
    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, buflen, NULL, NULL);

    if (!EncryptAndSaveFile(gDataDirA, gCurrentNote->fileName, text))
        MessageBox(NULL, L"Failed to save encrypted note.", L"Error", MB_ICONERROR);

    SecureZeroMemory(text, buflen);
    SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));
    free(text);
    free(wtext);
}

static int CalculatePasswordStrength(const char *password) {
    int length = strlen(password);
    int hasLower = 0, hasUpper = 0, hasDigit = 0, hasSpecial = 0;
    int score = 0;

    for (int i = 0; i < length; i++) {
        if (password[i] >= 'a' && password[i] <= 'z') hasLower = 1;
        else if (password[i] >= 'A' && password[i] <= 'Z') hasUpper = 1;
        else if (password[i] >= '0' && password[i] <= '9') hasDigit = 1;
        else if (password[i] >= 33 && password[i] <= 126) hasSpecial = 1;
    }

    if (hasLower) score += 1;
    if (hasUpper) score += 1;
    if (hasDigit) score += 1;
    if (hasSpecial) score += 1;
    if (length >= 12) score += 2;
    if (length >= 16) score += 1;

    return score; // range 0–7
}
