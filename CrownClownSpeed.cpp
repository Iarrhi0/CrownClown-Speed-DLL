
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <xinput.h>
#include <mmsystem.h>
#include <atomic>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "winmm.lib")

static HMODULE g_realXInput = nullptr;
static decltype(&XInputGetState) g_realGetState = nullptr;
static decltype(&XInputSetState) g_realSetState = nullptr;

static std::atomic<double> g_speed{1.0};

using QPC_t = BOOL (WINAPI*)(LARGE_INTEGER*);
using GTC_t = DWORD (WINAPI*)();
using TGT_t = DWORD (WINAPI*)();

static QPC_t g_realQPC = nullptr;
static GTC_t g_realGetTickCount = nullptr;
static TGT_t g_realTimeGetTime = nullptr;

static LARGE_INTEGER g_qpcRealBase{};
static LARGE_INTEGER g_qpcFakeBase{};
static DWORD g_gtcRealBase = 0;
static DWORD g_gtcFakeBase = 0;
static DWORD g_tgtRealBase = 0;
static DWORD g_tgtFakeBase = 0;

static CRITICAL_SECTION g_timeLock;

static void RebaseTime(double newSpeed)
{
    EnterCriticalSection(&g_timeLock);

    LARGE_INTEGER nowQpc{};
    g_realQPC(&nowQpc);
    const double oldSpeed = g_speed.load();
    const double elapsedQpc = double(nowQpc.QuadPart - g_qpcRealBase.QuadPart) * oldSpeed;
    g_qpcFakeBase.QuadPart += static_cast<LONGLONG>(elapsedQpc);
    g_qpcRealBase = nowQpc;

    DWORD nowGtc = g_realGetTickCount();
    DWORD elapsedGtc = static_cast<DWORD>((nowGtc - g_gtcRealBase) * oldSpeed);
    g_gtcFakeBase += elapsedGtc;
    g_gtcRealBase = nowGtc;

    DWORD nowTgt = g_realTimeGetTime();
    DWORD elapsedTgt = static_cast<DWORD>((nowTgt - g_tgtRealBase) * oldSpeed);
    g_tgtFakeBase += elapsedTgt;
    g_tgtRealBase = nowTgt;

    g_speed.store(newSpeed);
    LeaveCriticalSection(&g_timeLock);
}

static BOOL WINAPI HookQPC(LARGE_INTEGER* out)
{
    LARGE_INTEGER now{};
    if (!g_realQPC(&now)) return FALSE;

    EnterCriticalSection(&g_timeLock);
    const double scaled = double(now.QuadPart - g_qpcRealBase.QuadPart) * g_speed.load();
    out->QuadPart = g_qpcFakeBase.QuadPart + static_cast<LONGLONG>(scaled);
    LeaveCriticalSection(&g_timeLock);
    return TRUE;
}

static DWORD WINAPI HookGetTickCount()
{
    DWORD now = g_realGetTickCount();
    EnterCriticalSection(&g_timeLock);
    DWORD out = g_gtcFakeBase + static_cast<DWORD>((now - g_gtcRealBase) * g_speed.load());
    LeaveCriticalSection(&g_timeLock);
    return out;
}

static DWORD WINAPI HookTimeGetTime()
{
    DWORD now = g_realTimeGetTime();
    EnterCriticalSection(&g_timeLock);
    DWORD out = g_tgtFakeBase + static_cast<DWORD>((now - g_tgtRealBase) * g_speed.load());
    LeaveCriticalSection(&g_timeLock);
    return out;
}

static bool PatchIAT(HMODULE module, const char* dllName, const char* funcName, void* hook, void** original)
{
    auto base = reinterpret_cast<std::uint8_t*>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;

    auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc)
    {
        const char* importedDll = reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(importedDll, dllName) != 0) continue;

        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
        auto origThunk = desc->OriginalFirstThunk
            ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk)
            : thunk;

        for (; origThunk->u1.AddressOfData; ++origThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) continue;

            auto byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(byName->Name), funcName) != 0) continue;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect))
                return false;

            *original = reinterpret_cast<void*>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONGLONG>(hook);

            DWORD dummy = 0;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &dummy);
            FlushInstructionCache(GetCurrentProcess(), &thunk->u1.Function, sizeof(void*));
            return true;
        }
    }
    return false;
}

static DWORD WINAPI WorkerThread(void*)
{
    HMODULE mainModule = GetModuleHandleW(nullptr);

    InitializeCriticalSection(&g_timeLock);

    g_realQPC = &QueryPerformanceCounter;
    g_realGetTickCount = &GetTickCount;
    g_realTimeGetTime = &timeGetTime;

    g_realQPC(&g_qpcRealBase);
    g_qpcFakeBase = g_qpcRealBase;
    g_gtcRealBase = g_realGetTickCount();
    g_gtcFakeBase = g_gtcRealBase;
    g_tgtRealBase = g_realTimeGetTime();
    g_tgtFakeBase = g_tgtRealBase;

    void* original = nullptr;
    PatchIAT(mainModule, "KERNEL32.dll", "QueryPerformanceCounter", reinterpret_cast<void*>(&HookQPC), &original);
    PatchIAT(mainModule, "KERNEL32.dll", "GetTickCount", reinterpret_cast<void*>(&HookGetTickCount), &original);
    PatchIAT(mainModule, "WINMM.dll", "timeGetTime", reinterpret_cast<void*>(&HookTimeGetTime), &original);

    while (true)
    {
        if (GetAsyncKeyState(VK_F6) & 1) RebaseTime(1.00);
        if (GetAsyncKeyState(VK_F7) & 1) RebaseTime(1.10);
        if (GetAsyncKeyState(VK_F8) & 1) RebaseTime(1.20);
        if (GetAsyncKeyState(VK_F9) & 1) RebaseTime(1.30);
        Sleep(15);
    }
}

static bool LoadRealXInput()
{
    wchar_t systemDir[MAX_PATH]{};
    if (!GetSystemDirectoryW(systemDir, MAX_PATH)) return false;

    wchar_t path[MAX_PATH]{};
    wsprintfW(path, L"%s\\XINPUT9_1_0.dll", systemDir);

    g_realXInput = LoadLibraryW(path);
    if (!g_realXInput) return false;

    g_realGetState = reinterpret_cast<decltype(g_realGetState)>(
        GetProcAddress(g_realXInput, "XInputGetState"));
    g_realSetState = reinterpret_cast<decltype(g_realSetState)>(
        GetProcAddress(g_realXInput, "XInputSetState"));

    return g_realGetState && g_realSetState;
}

extern "C" __declspec(dllexport)
DWORD WINAPI XInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState)
{
    if (!g_realGetState && !LoadRealXInput()) return ERROR_DEVICE_NOT_CONNECTED;
    return g_realGetState(dwUserIndex, pState);
}

extern "C" __declspec(dllexport)
DWORD WINAPI XInputSetState(DWORD dwUserIndex, XINPUT_VIBRATION* pVibration)
{
    if (!g_realSetState && !LoadRealXInput()) return ERROR_DEVICE_NOT_CONNECTED;
    return g_realSetState(dwUserIndex, pVibration);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        LoadRealXInput();
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
