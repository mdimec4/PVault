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

#ifdef _WIN32
#define strdup _strdup
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
const int LABEL_WIDTH = 100;

HWND hTitleLabel;
static HBRUSH hLoginBrush = NULL;
static HBRUSH hEditorBrush = NULL;
static HBRUSH hBrushDisabled = NULL;
static HBRUSH hBrushEnabled = NULL;

static wchar_t gDataDirW[MAX_PATH] = {0};
static char    gDataDirA[MAX_PATH] = {0};

static md_linked_list_el* gNotes = NULL;
static NoteEntry* gCurrentNote = NULL;
static UINT_PTR gAutoSaveTimer = 0;
static BOOL gTextChanged = FALSE;

HWND hPasswordLabel, hPasswordEdit, hPasswordEdit2, hUnlockButton, hWipeButton, hImportButton;
HWND hStrengthBar, hHintLabel;
HWND hName, hUserName, hEmail, hUrl, hPassword, hOtherSecret, hLogoutButton;
HWND hUserNameLabel, hEmailLabel, hUrlLabel, hPasswordVaultLabel, hOtherSecretLabel;
HFONT hFont;
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
void LoadAndDecryptText(void);
void SaveEncryptedText(void);
static int CalculatePasswordStrength(const char *password);

static void NotesList_FreeAll(void)
{
    if (!gNotes)
        return;
    md_linked_list_free_all(gNotes, NotesEntry_Free);
    gNotes = NULL;
}

static void NotesList_LoadFromDb(HWND hNotesList)
{

    NotesList_FreeAll();
    SendMessageW(hNotesList, LB_RESETCONTENT, 0, 0);

    gNotes = LoadNotesList(NULL);
    for (md_linked_list_el* el = gNotes; el; el = el->next) {
        NoteEntry* n = (NoteEntry* )el->data;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, n->name, -1, NULL, 0);
        if (wlen <= 0) {
            continue;
        }
        wchar_t* wname = (wchar_t*)malloc(wlen * sizeof(wchar_t));
        if (!wname) {

            continue;
        }

        MultiByteToWideChar(CP_UTF8, 0, n->name, -1, wname, wlen);

        int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)wname);
        SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)n);
        free(wname);
    }
}

void InitStoragePath(void)
{
    // Get %LOCALAPPDATA%
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, gDataDirW)))
    {
        wcscat_s(gDataDirW, MAX_PATH, L"\\MyPasswordVault");
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
        MessageBox(NULL, L"Failed to initialize MyPasswordVault (libsodium error).", L"Fatal Error", MB_ICONERROR);
        return 1;
    }
    
    const wchar_t CLASS_NAME[] = L"MyPasswordVaultWindow";

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
        0, CLASS_NAME, L"MyPasswordVault",
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
        SaveEncryptedText();
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
        
        // Create brushes once
        hLoginBrush = CreateSolidBrush(COLOR_LOGIN_BG);
        hEditorBrush = CreateSolidBrush(COLOR_EDITOR_BG);
        
        hBrushEnabled = CreateSolidBrush(RGB(255,255,255));       // white
        hBrushDisabled = CreateSolidBrush(RGB(235,238,242));     // light gray
    
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
                 MessageBox(hwnd, L"Wrong password or failed to derive key.", L"Error", MB_ICONERROR);
             }

             return 0;
        }
        else if (LOWORD(wParam) == 1002) // Wipe storage
        {
            int result = MessageBoxW(
                hwnd,
                L"Are you sure you want to wipe your existing accounts storage? All accounts will be permanently lost!",
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
            /*
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
            */
            return 0;
        }
        else if (LOWORD(wParam) == 3000 && HIWORD(wParam) == LBN_SELCHANGE) {
            // Auto-save current note before switching
            if (gCurrentNote && gTextChanged) {
                SaveEncryptedText();
                gTextChanged = FALSE;
            }

            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                SaveEncryptedText();
                gCurrentNote = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
                if (gCurrentNote) {
                    LoadAndDecryptText();
                    gTextChanged = FALSE;
                    EnableWindow(hName, TRUE);
                    EnableWindow(hUserName, TRUE);
                    EnableWindow(hEmail, TRUE);
                    EnableWindow(hUrl, TRUE);
                    EnableWindow(hPassword, TRUE);
                    EnableWindow(hOtherSecret, TRUE);
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
                
                char noteNameUtf8[256];
                WideCharToMultiByte(CP_UTF8, 0, wNewName, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);

                // Check duplicates
                for (md_linked_list_el* el = gNotes; el; el = el->next) {
                    NoteEntry* ne = (NoteEntry*)el->data;
                    if (strncmp(ne->name, noteNameUtf8, sizeof(noteNameUtf8)) == 0) {
                        MessageBox(hwnd, L"Note already exists.", L"Error", MB_ICONERROR);
                        return 0;
                    }
                }



                // Create note entry
                NoteEntry* n = calloc(1, sizeof(NoteEntry));
                if (!n)
                    return 0;
                n->id = -1LL;
                n-> name = strdup(noteNameUtf8);
               
               // prepend to linked list
               md_linked_list_el* new_el = calloc(1, sizeof(md_linked_list_el));
               if (!new_el)
                   return 0;
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
                    
                    int idx = (int)SendMessageA(hNotesList, LB_ADDSTRING, 0, (LPARAM)ne->name);
                    SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)ne);
                    if (isNewElement)
                    {
                        SendMessageW(hNotesList, LB_SETCURSEL, idx, 0);
                        isNewElement = FALSE;
                    }
                }
                    
                gCurrentNote = n;
                SetWindowTextW(hName, wNewName);
                SetWindowTextW(hUserName, L"");
                SetWindowTextW(hEmail, L"");
                SetWindowTextW(hUrl, L"");
                SetWindowTextW(hPassword, L"");
                SetWindowTextW(hOtherSecret, L"");
                EnableWindow(hName, TRUE);
                EnableWindow(hUserName, TRUE);
                EnableWindow(hEmail, TRUE);
                EnableWindow(hUrl, TRUE);
                EnableWindow(hPassword, TRUE);
                EnableWindow(hOtherSecret, TRUE);
                gTextChanged = FALSE;
                
                NoteData* nd = NoteData_New(n->id, n->name, "", "", "", "", "", 0, 0);
                InsertOrUpdateNoteData(nd);
                n->id = nd->id;
                NoteData_Free(nd);
            }
        }
        else if (LOWORD(wParam) == 3002) { // Delete
            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR) return 0;

            NoteEntry* n = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
            if (!n) return 0;

            if (n->id != -1LL)
                DeleteNoteData(n->id);
            
            SendMessage(hNotesList, LB_DELETESTRING, sel, 0);

            // Remove from linked list
            md_linked_list_el* remove_el = gNotes;
            while(remove_el && remove_el->data != n) remove_el = remove_el-> next;
            if (remove_el)
                gNotes = md_linked_list_remove(gNotes, remove_el, NotesEntry_Free);

            gCurrentNote = NULL;
            WipeWindowText(hName);
            WipeWindowText(hUserName);
            WipeWindowText(hEmail);
            WipeWindowText(hUrl);
            WipeWindowText(hPassword);
            WipeWindowText(hOtherSecret);
            EnableWindow(hName, FALSE);
            EnableWindow(hUserName, FALSE);
            EnableWindow(hEmail, FALSE);
            EnableWindow(hUrl, FALSE);
            EnableWindow(hPassword, FALSE);
            EnableWindow(hOtherSecret, FALSE);
        }
        else if (LOWORD(wParam) == 3003) { // EXPORT
           /* char* suggestedName = MakeSecureNotesZipFilename();

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
            }*/
        }
        else if (HIWORD(wParam) == EN_CHANGE && ((HWND)lParam == hUserName || (HWND)lParam == hEmail || (HWND)lParam == hUrl || (HWND)lParam == hPassword || (HWND)lParam == hOtherSecret)) {
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
                SaveEncryptedText();
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
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;

        // Is this actually a disabled edit control?
        TCHAR cls[32];
        GetClassName(hCtl, cls, 32);

        if (!_wcsicmp(cls, L"Edit") && !IsWindowEnabled(hCtl))
        {
            SetBkColor(hdc, RGB(235,238,242));   // disabled
            return (INT_PTR)hBrushDisabled;
        }

        // For real static labels: use background (transparent)
        SetBkMode(hdc, TRANSPARENT);
        return (INT_PTR)GetStockObject(NULL_BRUSH);
    }
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORLISTBOX:
    {
        HDC hdc = (HDC)wParam;

        // Text style
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(32, 32, 32));

        // Return proper background brush
        return (INT_PTR)(isUnlocked ? hEditorBrush : hLoginBrush);
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;

        if (!IsWindowEnabled(hCtl)) {
            // Disabled EDIT → Windows sends WM_CTLCOLORSTATIC, but handle both
            SetBkColor(hdc, RGB(235,238,242));
            return (INT_PTR)hBrushDisabled;
        }

        SetBkColor(hdc, RGB(255,255,255));
        return (INT_PTR)hBrushEnabled;
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
            MoveWindow(hName, listWidth + MARGIN, MARGIN,
                   rc.right - listWidth - 2 * MARGIN,
                   40, TRUE);
            MoveWindow(hUserName, listWidth + MARGIN, 2 * MARGIN + 40,
                   rc.right - listWidth - 2 * MARGIN,
                   40, TRUE);
            MoveWindow(hEmail, listWidth + MARGIN, 3 * MARGIN + 2 * 40,
                   rc.right - listWidth - 2 * MARGIN,
                   40, TRUE);
            MoveWindow(hUrl, listWidth + MARGIN, 4 * MARGIN + 3 * 40,
                   rc.right - listWidth - 2 * MARGIN,
                   40, TRUE);
            MoveWindow(hPassword, listWidth + MARGIN, 5 * MARGIN + 4 * 40,
                   rc.right - listWidth - 2 * MARGIN,
                   40, TRUE);
            MoveWindow(hOtherSecret, listWidth + MARGIN, 6 * MARGIN + 5 * 40,
                   rc.right - listWidth - 2 * MARGIN,
                   listHeight - 5 * MARGIN - 5 * 40, TRUE);
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
            SaveEncryptedText();
            gTextChanged = FALSE;
        }
        NotesList_FreeAll();
        
        if (hName && IsWindow(hName)) {
            WipeWindowText(hName);
            DestroyWindow(hName);
        }
        if (hUserNameLabel && IsWindow(hUserNameLabel)) {
            DestroyWindow(hUserNameLabel);
        }
        if (hUserName && IsWindow(hUserName)) {
            WipeWindowText(hUserName);
            DestroyWindow(hUserName);
        }
        if (hEmailLabel && IsWindow(hEmailLabel)) {
            DestroyWindow(hEmailLabel);
        }
        if (hEmail && IsWindow(hEmail)) {
            WipeWindowText(hEmail);
            DestroyWindow(hEmail);
        }
        if (hUrlLabel && IsWindow(hUrlLabel)) {
            DestroyWindow(hUrlLabel);
        }
        if (hUrl && IsWindow(hUrl)) {
            WipeWindowText(hUrl);
            DestroyWindow(hUrl);
        }
        if (hPasswordVaultLabel && IsWindow(hPasswordVaultLabel)) {
            DestroyWindow(hPasswordVaultLabel);
        }
        if (hPassword && IsWindow(hPassword)) {
            WipeWindowText(hPassword);
            DestroyWindow(hPassword);
        }
        if (hOtherSecretLabel && IsWindow(hOtherSecretLabel)) {
            DestroyWindow(hOtherSecretLabel);
        }
        if (hOtherSecret && IsWindow(hOtherSecret)) {
            WipeWindowText(hOtherSecret);
            DestroyWindow(hOtherSecret);
        }
        
        if (hLoginBrush) { DeleteObject(hLoginBrush); hLoginBrush = NULL; }
        if (hEditorBrush) { DeleteObject(hEditorBrush); hEditorBrush = NULL; }
        
        if (hBrushDisabled) { DeleteObject(hBrushDisabled); hBrushDisabled = NULL; }
        if (hBrushEnabled) { DeleteObject(hBrushEnabled); hBrushEnabled = NULL; }
        
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

    hTitleLabel = CreateWindow(L"static", L"MyPasswordVault",
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
        L"BUTTON", L"New",
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

    //
    // name label
    hName = CreateWindowEx(0, L"STATIC",
        L"",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        listWidth + MARGIN, MARGIN, rc.right - listWidth - 2 * MARGIN, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hName, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hName, L"", L"");
    
    hUserNameLabel = CreateWindowEx(0, L"STATIC",
        L"User name:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        listWidth + MARGIN, 2 * MARGIN + BUTTON_HEIGHT, LABEL_WIDTH, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hUserNameLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hUserNameLabel, L"", L"");
    
    hUserName = CreateWindowEx(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        listWidth + 2* MARGIN + LABEL_WIDTH, 2 * MARGIN + BUTTON_HEIGHT, rc.right - listWidth - 3 * MARGIN - LABEL_WIDTH - 2 * (MARGIN + BUTTON_WIDTH), BUTTON_HEIGHT,
        hwnd, (HMENU)2497, NULL, NULL);
    SetWindowTheme(hUserName, L"", L"");
    SendMessage(hUserName, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    hEmailLabel = CreateWindowEx(0, L"STATIC",
        L"Email:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        listWidth + MARGIN, 3 * MARGIN + 2 * BUTTON_HEIGHT, LABEL_WIDTH, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hEmailLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hEmailLabel, L"", L"");
    
    hEmail = CreateWindowEx(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        listWidth + 2* MARGIN + LABEL_WIDTH, 3 * MARGIN + 2 * BUTTON_HEIGHT, rc.right - listWidth - 3 * MARGIN - LABEL_WIDTH - 2 * (MARGIN + BUTTON_WIDTH), BUTTON_HEIGHT,
        hwnd, (HMENU)2498, NULL, NULL);
    SetWindowTheme(hEmail, L"", L"");
    SendMessage(hEmail, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    hUrlLabel = CreateWindowEx(0, L"STATIC",
        L"URL:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        listWidth + MARGIN, 4 * MARGIN + 3 * BUTTON_HEIGHT, LABEL_WIDTH, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hUrlLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hUrlLabel, L"", L"");
    
    hUrl = CreateWindowEx(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        listWidth + 2* MARGIN + LABEL_WIDTH, 4 * MARGIN + 3 * BUTTON_HEIGHT, rc.right - listWidth - 3 * MARGIN - LABEL_WIDTH - 2 * (MARGIN + BUTTON_WIDTH), BUTTON_HEIGHT,
        hwnd, (HMENU)2498, NULL, NULL);
    SetWindowTheme(hUrl, L"", L"");
    SendMessage(hUrl, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    hPasswordVaultLabel = CreateWindowEx(0, L"STATIC",
        L"Password:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        listWidth + MARGIN, 5 * MARGIN + 4 * BUTTON_HEIGHT, LABEL_WIDTH, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hPasswordVaultLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hPasswordVaultLabel, L"", L"");
    
    hPassword = CreateWindowEx(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
        listWidth + 2* MARGIN + LABEL_WIDTH, 5 * MARGIN + 4 * BUTTON_HEIGHT, rc.right - listWidth - 3 * MARGIN - LABEL_WIDTH - 2 * (MARGIN + BUTTON_WIDTH), BUTTON_HEIGHT,
        hwnd, (HMENU)2499, NULL, NULL);
    SetWindowTheme(hPassword, L"", L"");
    SendMessage(hPassword, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    hOtherSecretLabel = CreateWindowEx(0, L"STATIC",
        L"Other secrets:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        listWidth + MARGIN, 6 * MARGIN + 5 * BUTTON_HEIGHT, LABEL_WIDTH, BUTTON_HEIGHT,
        hwnd, NULL, GetModuleHandle(NULL), NULL);
    SendMessage(hOtherSecretLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(hOtherSecretLabel, L"", L"");
    
        // Rich Edit for note text
    hOtherSecret = CreateWindowEx(
        0, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        listWidth + 2* MARGIN + LABEL_WIDTH, 6 * MARGIN + 5 * BUTTON_HEIGHT,rc.right - listWidth - 3 * MARGIN - LABEL_WIDTH - 2 * (MARGIN + BUTTON_WIDTH), listHeight - 5 * MARGIN - 5 * BUTTON_HEIGHT,
        hwnd, (HMENU)2500, NULL, NULL);
    SetWindowTheme(hOtherSecret, L"", L"");
    SendMessage(hOtherSecret, WM_SETFONT, (WPARAM)hFont, TRUE);
    //
    
        
    // Subscribe to EN_CHANGE notifications
    SendMessage(hUserName, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    SendMessage(hEmail, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    SendMessage(hUrl, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    SendMessage(hPassword, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    SendMessage(hOtherSecret, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_UPDATE);
    
    NotesList_LoadFromDb(hNotesList);
    
    EnableWindow(hName, FALSE);
    EnableWindow(hUserName, FALSE);
    EnableWindow(hEmail, FALSE);
    EnableWindow(hUrl, FALSE);
    EnableWindow(hPassword, FALSE);
    EnableWindow(hOtherSecret, FALSE);

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
        MessageBox(hwnd, L"No accounts found. Please create a new acount to begin.", L"Welcome", MB_ICONINFORMATION);
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
        // Securely clear text before destroying the editor control
    if (hName && IsWindow(hName)) {
        DestroyWindow(hName);
        hName = NULL;
    }
    if (hUserNameLabel && IsWindow(hUserNameLabel)) {
        DestroyWindow(hUserNameLabel);
        hUserNameLabel = NULL;
    }
    if (hUserName && IsWindow(hUserName)) {
        WipeWindowText(hUserName);
        DestroyWindow(hUserName);
        hUserName = NULL;
    }
    if (hEmailLabel && IsWindow(hEmailLabel)) {
        DestroyWindow(hEmailLabel);
        hEmailLabel = NULL;
    }
    if (hEmail && IsWindow(hEmail)) {
        WipeWindowText(hEmail);
        DestroyWindow(hEmail);
        hEmail = NULL;
    }
    if (hUrlLabel && IsWindow(hUrlLabel)) {
        DestroyWindow(hUrlLabel);
        hUrlLabel = NULL;
    }
    if (hUrl && IsWindow(hUrl)) {
        WipeWindowText(hUrl);
        DestroyWindow(hUrl);
        hUrl = NULL;
    }
    if (hPasswordVaultLabel && IsWindow(hPasswordVaultLabel)) {
        DestroyWindow(hPasswordVaultLabel);
        hPasswordVaultLabel = NULL;
    }
    if (hPassword && IsWindow(hPassword)) {
        WipeWindowText(hPassword);
        DestroyWindow(hPassword);
        hPassword = NULL;
    }
    if (hOtherSecretLabel && IsWindow(hOtherSecretLabel)) {
        DestroyWindow(hOtherSecretLabel);
        hOtherSecretLabel = NULL;
    }
    if (hOtherSecret && IsWindow(hOtherSecret)) {
        WipeWindowText(hOtherSecret);
        DestroyWindow(hOtherSecret);
        hOtherSecret = NULL;
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

void LoadAndDecryptText(void)
{
    if (!gCurrentNote || gCurrentNote->id == -1LL) {
        SetWindowTextW(hName, L"");
        SetWindowTextW(hUserName, L"");
        SetWindowTextW(hEmail, L"");
        SetWindowTextW(hUrl, L"");
        SetWindowTextW(hPassword, L"");
        SetWindowTextW(hOtherSecret, L"");
        return;
    }

    NoteData* nd = GetNoteData(gCurrentNote->id);
    if (!nd)
    {
        SetWindowTextW(hName, L"");
        SetWindowTextW(hUserName, L"");
        SetWindowTextW(hEmail, L"");
        SetWindowTextW(hUrl, L"");
        SetWindowTextW(hPassword, L"");
        SetWindowTextW(hOtherSecret, L"");
        return;
    }


    SetWindowTextA(hName, nd->name);

    SetWindowTextA(hUserName, nd->userName);
    
    SetWindowTextA(hEmail, nd->email);

    SetWindowTextA(hUrl, nd->url);

    SetWindowTextA(hPassword, nd->password);
    
    SetWindowTextA(hOtherSecret, nd->otherSecret);
    
    NoteData_Free(nd);
}

char* GetWText(HWND hwnd)
{
    if (!hwnd) return NULL;
    
    int len = GetWindowTextLengthA(hwnd);
    if (len < 0) return NULL;

    char* text = malloc(len + 1);
    if (!text) return NULL;
    GetWindowTextA(hwnd, text, len + 1);
    return text;
}

void SaveEncryptedText(void)
{
    if (!gCurrentNote)
        return;

    NoteData* nd = calloc(1, sizeof(NoteData));
    nd->id = gCurrentNote->id;
    nd->name = strdup(gCurrentNote->name);
    nd->userName = GetWText(hUserName);
    nd->email = GetWText(hEmail);
    nd->url = GetWText(hUrl);
    nd->password = GetWText(hPassword);
    nd->otherSecret = GetWText(hOtherSecret);

    if (InsertOrUpdateNoteData(nd) != 0)
        MessageBox(NULL, L"Failed to save encrypted account.", L"Error", MB_ICONERROR);
    gCurrentNote->id = nd->id;
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
