#ifndef MODERN_UI_H
#define MODERN_UI_H

#include <windows.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <stdbool.h>

#ifdef _MSC_VER
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Apply global DWM/Fluent styling to a top-level window
void InitModernUI(HWND hwnd);

// Create a Segoe UI Variable font (recommended for modern apps)
HFONT CreateModernUIFont(int size, bool bold);

// Enable modern look for a standard button (rounded edges, subtle hover)
void ApplyModernButton(HWND hwndButton);

// Paint background (call from WM_ERASEBKGND)
void PaintModernBackground(HWND hwnd, HDC hdc, BOOL darkMode, COLORREF accentColor);

BOOL ModernUI_HandleDrawItem(LPARAM lParam);
#ifdef __cplusplus
}
#endif

#endif // MODERN_UI_H
