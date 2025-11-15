#include "modern_ui.h"
#include <dwmapi.h>
#include <uxtheme.h>
#include <vssym32.h>

void InitModernUI(HWND hwnd)
{
    // Rounded corners (Windows 11+)
    const int DWMWCP_ROUND = 2;
    const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE,
                          &DWMWCP_ROUND, sizeof(DWMWCP_ROUND));

    // Optional: use system backdrop (Mica / Acrylic)
    // 38 = DWMWA_SYSTEMBACKDROP_TYPE, 2 = Mica
    const int DWMSBT_MAINWINDOW = 2;
    DwmSetWindowAttribute(hwnd, 38, &DWMSBT_MAINWINDOW, sizeof(DWMSBT_MAINWINDOW));

    // Enable immersive dark mode if the system supports it
    BOOL dark = FALSE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark)); // DWMWA_USE_IMMERSIVE_DARK_MODE
}

HFONT CreateModernUIFont(int size, bool bold)
{
    LOGFONTW lf = {0};
    lf.lfHeight = -size;
    lf.lfWeight = bold ? FW_SEMIBOLD : FW_NORMAL;
    wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI Variable Text");
    return CreateFontIndirectW(&lf);
}

// Helper for rounded button painting
static void DrawRoundedButton(HDC hdc, RECT rc, LPCWSTR text, BOOL hovered, BOOL pressed)
{
    int radius = 8;
    COLORREF bg = RGB(248, 249, 250);
    COLORREF border = RGB(210, 210, 210);

    if (pressed)
        bg = RGB(230, 230, 230);
    else if (hovered)
        bg = RGB(242, 242, 242);

    HBRUSH brush = CreateSolidBrush(bg);
    HPEN pen = CreatePen(PS_SOLID, 1, border);

    HGDIOBJ oldBrush = SelectObject(hdc, brush);
    HGDIOBJ oldPen = SelectObject(hdc, pen);

    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(32, 32, 32));
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void ApplyModernButton(HWND hwndButton)
{
    LONG_PTR style = GetWindowLongPtr(hwndButton, GWL_STYLE);
    SetWindowLongPtr(hwndButton, GWL_STYLE, style | BS_OWNERDRAW);
}

// In your main WndProc, handle WM_DRAWITEM:
BOOL ModernUI_HandleDrawItem(LPARAM lParam)
{
    DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lParam;
    if (dis->CtlType == ODT_BUTTON)
    {
        BOOL hovered = (dis->itemState & ODS_HOTLIGHT) != 0;
        BOOL pressed = (dis->itemState & ODS_SELECTED) != 0;
        WCHAR text[128];
        GetWindowTextW(dis->hwndItem, text, 128);
        DrawRoundedButton(dis->hDC, dis->rcItem, text, hovered, pressed);
        return TRUE;
    }
    return FALSE;
}

void PaintModernBackground(HWND hwnd, HDC hdc, BOOL darkMode, COLORREF accentColor)
{
    RECT rc;
    GetClientRect(hwnd, &rc);

    COLORREF bg = darkMode ? RGB(32, 32, 32) : RGB(245, 247, 250);
    HBRUSH brush = CreateSolidBrush(bg);
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    if (accentColor != CLR_INVALID)
    {
        HPEN pen = CreatePen(PS_SOLID, 1, accentColor);
        HGDIOBJ oldPen = SelectObject(hdc, pen);
        MoveToEx(hdc, rc.left, rc.top, NULL);
        LineTo(hdc, rc.right, rc.top);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
    }
}
