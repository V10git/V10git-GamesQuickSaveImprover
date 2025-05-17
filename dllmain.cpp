#include <Windows.h>
#include <iostream>
#include <string>
#include "MinHook.h"

#pragma comment( lib, "lib\\libMinHook-x64-v141-md.lib" )

#define LAST_QUICKSAVE_NUMBER_FILENAME "_last_quicksave_number.tmp"
#define GAMESAVE_PATH_DELIM L"/"
#define QUICKSAVE_FILENAME L"quicksave"
#define QUICKSAVE_EXTENSION L".dat"
#define QUICKSAVE_FULL_FILENAME L"quicksave.dat"
#define MAX_QUICKSAVE_COUNT 8

bool exists(const std::wstring& name);
bool exists(const std::string& name);
bool readfile(const char* filename, char* buff, DWORD buffsize);
void writefile(const char* filename, const unsigned char* pData, DWORD nSize);

typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

CreateFileW_t OriginalCreateFileW = nullptr;
LPVOID g_pKB_CreateFileWHook = nullptr;

int g_nQuickSave = 0;
int g_nMaxQuickSave = MAX_QUICKSAVE_COUNT;
std::wstring g_sNewQuickSaveFileName = L"";

HANDLE HookedCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    //std::cout << "Working" << std::endl;
    if (lpFileName != NULL && 
        (dwDesiredAccess & GENERIC_WRITE) == GENERIC_WRITE &&
        (dwCreationDisposition == CREATE_ALWAYS || dwCreationDisposition == CREATE_NEW)) {
        std::wcout << "Saving to " << lpFileName << std::endl;
        std::wstring fname = lpFileName;
        if (fname.find(QUICKSAVE_FULL_FILENAME) != std::string::npos)
        {
            std::wcout << "quicksave detected" << std::endl;
            if (g_nQuickSave > 0)
            {
                WCHAR tmp[10] = { 0 };
                _itow_s(g_nQuickSave, tmp, sizeof(tmp), 10);

                g_sNewQuickSaveFileName = fname.substr(0, fname.find_last_of(L"/\\"));
                g_sNewQuickSaveFileName += GAMESAVE_PATH_DELIM;
                g_sNewQuickSaveFileName += QUICKSAVE_FILENAME;
                g_sNewQuickSaveFileName += tmp;
                g_sNewQuickSaveFileName += QUICKSAVE_EXTENSION;
                std::wcout << "New quicksave filename = " << g_sNewQuickSaveFileName << std::endl;
                lpFileName = g_sNewQuickSaveFileName.c_str();
            }

            g_nQuickSave++;
            if (g_nQuickSave > g_nMaxQuickSave)
                g_nQuickSave = 0;

            char tmp2[10] = { 0 };
            _itoa_s(g_nQuickSave, tmp2, sizeof(tmp2), 10);
            MH_DisableHook(g_pKB_CreateFileWHook);
            writefile(LAST_QUICKSAVE_NUMBER_FILENAME, (const unsigned char*)tmp2, strlen(tmp2));
            MH_EnableHook(g_pKB_CreateFileWHook);
        }

    }

    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

VOID Hook()
{
    AllocConsole();
    FILE* fOut;
    freopen_s(&fOut, "CONOUT$", "w", stdout);
    std::cout << "Games Quick Save Improver injected!" << std::endl;

    // TODO: store file in TEMP or my dll path
    if (exists(LAST_QUICKSAVE_NUMBER_FILENAME))
    {
        char tmp[10] = { 0 };
        if (readfile(LAST_QUICKSAVE_NUMBER_FILENAME, tmp, sizeof(tmp)) && strlen(tmp) > 0)
            g_nQuickSave = atoi(tmp);
        if (g_nQuickSave > g_nMaxQuickSave)
            g_nQuickSave = 0;
    }

    if ((g_pKB_CreateFileWHook = GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "CreateFileW")) == nullptr ||
        MH_Initialize() != MH_OK ||
        MH_CreateHook(g_pKB_CreateFileWHook, &HookedCreateFileW, reinterpret_cast<LPVOID*>(&OriginalCreateFileW)) != MH_OK ||
        MH_EnableHook(g_pKB_CreateFileWHook) != MH_OK) {
        std::cout << "Hooking ERROR!" << std::endl;
        return;
    }

    std::cout << "Calls hooked" << std::endl;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Hook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

bool exists(const std::string& name)
{
    struct _stat buffer;
    return (_stat(name.c_str(), &buffer) == 0);
}


bool exists(const std::wstring& name)
{
    struct _stat buffer;
    return (_wstat(name.c_str(), &buffer) == 0);
}

bool readfile(const char* filename, char* buff, DWORD buffsize)
{
    try {
        FILE* fd;
        if (!fopen_s(&fd, filename, "rb"))
        {
            ZeroMemory(buff, buffsize);
            fread(buff, 1, buffsize, fd);
            fclose(fd);
        }
        else {
            return false;
        }
    }
    catch (...) {}
    return true;
}

void writefile(const char* filename, const unsigned char* pData, DWORD nSize)
{
    try {
        FILE* fd;
        if (!fopen_s(&fd, filename, "wb"))
        {
            fwrite(pData, nSize, 1, fd);
            fclose(fd);
        }
        else {
            return;
        }
    }
    catch (...) {}
}

