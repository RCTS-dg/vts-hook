#include <windows.h>
#include <string>
#include <filesystem>
#include <set>
#include <mutex>
#include "MinHook.h"

namespace fs = std::filesystem;
typedef HANDLE(WINAPI* CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CREATEFILEW pCreateFileW = NULL;
std::mutex g_Mtx;
std::set<std::wstring> g_ProcessedFolders; 
thread_local bool g_InHook = false;
void CopyModelFolder(LPCWSTR lpFileName) {
    std::wstring filePath(lpFileName);
    if (filePath.find(L".model3.json") != std::wstring::npos) {
        std::lock_guard<std::mutex> lock(g_Mtx);
        try {
            fs::path sourceFile(filePath);
            fs::path sourceDir = sourceFile.parent_path();
            std::wstring folderName = sourceDir.filename().wstring();
            if (g_ProcessedFolders.count(folderName)) return;
            fs::path targetRoot = L"C:\\VTS_Dump";
            fs::path targetDir = targetRoot / folderName;
            if (!fs::exists(targetRoot)) {
                fs::create_directories(targetRoot);
            }
            fs::copy(sourceDir, targetDir, fs::copy_options::recursive | fs::copy_options::overwrite_existing);

            g_ProcessedFolders.insert(folderName);
            OutputDebugStringW((L"[VTS-Hook] 成功备份整个目录: " + folderName).c_str());
        }
        catch (const std::exception& e) {
            std::string errMsg = "[VTS-Hook] 异常: ";
            errMsg += e.what();
            OutputDebugStringA(errMsg.c_str());
        }
    }
}

HANDLE WINAPI DetourCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (g_InHook) {
        return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    g_InHook = true;
    if (lpFileName != NULL) {
        CopyModelFolder(lpFileName);
    }
    g_InHook = false;
    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void StartHook() {
    if (MH_Initialize() == MH_OK) {
        if (MH_CreateHookApi(L"kernel32.dll", "CreateFileW", &DetourCreateFileW, reinterpret_cast<LPVOID*>(&pCreateFileW)) == MH_OK) {
            MH_EnableHook(MH_ALL_HOOKS);
            OutputDebugStringA("[VTS-Hook] Hook 注入成功并已启动");
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        StartHook();
        break;
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}