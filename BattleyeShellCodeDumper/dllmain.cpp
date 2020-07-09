#define _CRT_SECURE_NO_WARNINGS

#include <vector>
#include <Windows.h>
#include "lazy_importer.h"
#include "xor.h"



bool IsValidPtr(void* pointer)
{
    constexpr auto minimum_application_address = intptr_t(0x00010000);
    constexpr auto maximum_application_address = intptr_t(0x7FFFFFFEFFFF);
    return !(reinterpret_cast<intptr_t>(pointer) < minimum_application_address || reinterpret_cast<intptr_t>(pointer) >
             maximum_application_address) && pointer;
}

int LockLibraryIntoProcessMem(HMODULE dllHandle, HMODULE* localDllHandle)
{
    if (nullptr == localDllHandle)
        return ERROR_INVALID_PARAMETER;


    *localDllHandle = nullptr;

    TCHAR moduleName[1024];

    if (0 == iat(GetModuleFileNameW).cached()(dllHandle, moduleName, sizeof moduleName / sizeof(TCHAR)))
        return iat(GetLastError).cached()();

    *localDllHandle = iat(LoadLibraryW).cached()(moduleName);

    if (nullptr == *localDllHandle)
        return iat(GetLastError).cached()();


    return NO_ERROR;
}

uintptr_t PatternScan(const uintptr_t moduleAdress, const char* signature)
{
    static auto patternToByte = [](const char* pattern)
    {
        auto       bytes = std::vector<int>{};
        const auto start = const_cast<char*>(pattern);
        const auto end   = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else { bytes.push_back(strtoul(current, &current, 16)); }
        }
        return bytes;
    };

    const auto dosHeader = (PIMAGE_DOS_HEADER)moduleAdress;
    const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)moduleAdress + dosHeader->e_lfanew);

    const auto sizeOfImage  = ntHeaders->OptionalHeader.SizeOfImage;
    auto       patternBytes = patternToByte(signature);
    const auto scanBytes    = reinterpret_cast<std::uint8_t*>(moduleAdress);

    const auto s = patternBytes.size();
    const auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i)
    {
        bool found = true;
        for (auto j = 0ul; j < s; ++j)
        {
            if (scanBytes[i + j] != d[j] && d[j] != -1)
            {
                found = false;
                break;
            }
        }
        if (found) { return reinterpret_cast<uintptr_t>(&scanBytes[i]); }
    }
    return NULL;
}

bool CreateHook(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pOriginal)
{
    using CreateHook_t = uint64_t(__fastcall*)(LPVOID, LPVOID, LPVOID*);
    static CreateHook_t fnCreateHook = nullptr;


    if (!IsValidPtr(fnCreateHook))
    {
        fnCreateHook = (CreateHook_t)PatternScan((uintptr_t)GetModuleHandle(xorstr_(L"DiscordHook64.dll").c_str()),
                                                 xorstr_(
                                                     "40 53 55 56 57 41 54 41 56 41 57 48 83 EC 60").
                                                 c_str());
    }

    if (!IsValidPtr(fnCreateHook))
    {
        printf(xorstr_("[FAIL] CreateHook was NULL").c_str());
        return false;
    }


    return fnCreateHook((void*)originalPresent, (void*)originalHooked,
                        (void**)pOriginal) == 0
               ? true
               : false;
}

bool EnableHook(uintptr_t pTarget, bool toggle)
{
    using EnableHook_t = uint64_t(__fastcall*)(LPVOID, bool);
    static EnableHook_t fnEnableHook = nullptr;

    if (!IsValidPtr(fnEnableHook))
    {
        fnEnableHook = (EnableHook_t)PatternScan((uintptr_t)GetModuleHandle(xorstr_(L"DiscordHook64.dll").c_str()),
                                                 xorstr_(
                                                     "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 33 F6 8B FA")
                                                 .c_str());
    }

    if (!IsValidPtr(fnEnableHook))
    {
        printf(xorstr_("[FAIL] EnableHook was NULL").c_str());
        return false;
    }

    return fnEnableHook((void*)pTarget, toggle) == 0 ? true : false;
}

bool EnableHookQue()
{
    using EnableHookQueu_t = uint64_t(__stdcall*)(VOID);
    static EnableHookQueu_t fnEnableHookQueu = nullptr;

    if (!IsValidPtr(fnEnableHookQueu))
    {
        fnEnableHookQueu = (EnableHookQueu_t)PatternScan(
            (uintptr_t)GetModuleHandle(xorstr_(L"DiscordHook64.dll").c_str()),
            xorstr_(
                "48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 57")
            .c_str());
    }

    if (!IsValidPtr(fnEnableHookQueu))
    {
        printf(xorstr_("[FAIL] EnableHookQue was NULL").c_str());
        return false;
    }

    return fnEnableHookQueu() == 0 ? true : false;
}

bool HookFunction(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pTrampolim)
{
    if (CreateHook(originalPresent, originalHooked, pTrampolim))
    {
        if (EnableHook(originalPresent, true))
        {
            if (EnableHookQue())
            {
                return true;
            }
        }
    }

    return false;
}

void AttachConsole()
{
    iat(AllocConsole).cached()();
    freopen(xorstr_("CONOUT$").c_str(), "w", stdout);
}


using CreateFileA_t = HANDLE(__stdcall*)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);


using CreateFileW_t = HANDLE (__stdcall*)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);


using WriteFile_t = BOOL (__stdcall*)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

using WriteFileEx_t = BOOL (__stdcall*)(
    HANDLE                          hFile,
    LPCVOID                         lpBuffer,
    DWORD                           nNumberOfBytesToWrite,
    LPOVERLAPPED                    lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);


CreateFileA_t orig_CreateFileA;
CreateFileW_t orig_CreateFileW;
WriteFile_t   orig_WriteFile;
WriteFileEx_t orig_WriteFileEx;


HANDLE BE_StreamedHandle = nullptr;

HANDLE CreateFileA_Hk(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    // If we found BEClient2
    if (strstr(lpFileName, xorstr_("BEClient2").c_str()) != nullptr)
    {
        printf(xorstr_("\n\n-----------[ Battleye Streamed BEClient2 ] -----------\n").c_str());
        printf(xorstr_("USING: CreateFileA.\n").c_str());
        printf(xorstr_("SAVE PATH: %s.\n").c_str(), lpFileName);

        // Get the handle to where it wants to save.
        auto tempHandle = orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                           dwCreationDisposition,
                                           dwFlagsAndAttributes, hTemplateFile);

        printf(xorstr_("HANDLE: %d.\n").c_str(), tempHandle);
        printf(xorstr_("-------------------------------------------------------------\n\n").c_str());

        BE_StreamedHandle = tempHandle;

        return tempHandle;
    }
    if (strstr(lpFileName, xorstr_("BattlEye").c_str()) != nullptr)
    {
        printf(xorstr_("[Battleye-Stuf]: %s \n").c_str(), lpFileName);
    }
    else
    {
        printf(xorstr_("[HK-CreateFileA]: %s \n").c_str(), lpFileName);
    }

    return orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}

HANDLE CreateFileW_Hk(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    // If we found BEClient2
    if (wcsstr(lpFileName, xorstr_(L"BEClient2").c_str()) != nullptr)
    {
        printf(xorstr_("\n\n-----------[ Battleye Streamed BEClient2 ] -----------\n").c_str());
        printf(xorstr_("USING: CreateFileA.\n").c_str());
        printf(xorstr_("SAVE PATH: %ls.\n").c_str(), lpFileName);
        printf(xorstr_("DESIRE AACCESS: %d.\n").c_str(), dwShareMode);

        // Get the handle to where it wants to save.
        auto tempHandle = orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                           dwCreationDisposition,
                                           dwFlagsAndAttributes, hTemplateFile);

        printf(xorstr_("HANDLE: %p.\n").c_str(), tempHandle);
        printf(xorstr_("-------------------------------------------------------------\n\n").c_str());

        BE_StreamedHandle = tempHandle;

        return tempHandle;
    }
    if (wcsstr(lpFileName, xorstr_(L"BattlEye").c_str()) != nullptr)
    {
        printf(xorstr_("[BE-Stuff]: %ls \n").c_str(), lpFileName);
    }
    else
    {
        printf(xorstr_("[HK-CreateFileW]: %ls \n").c_str(), lpFileName);
    }

    return orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}


bool WriteFile_Hk(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
)
{
    // Check if BE_StreamedHandle is not null, if its not, it means that be streamed the module, then, check if the current file to be save is the streamed module.
    if (BE_StreamedHandle != nullptr && hFile == BE_StreamedHandle)
    {
        printf(xorstr_("\n\n-----------[ Saving BEClient2 ] -----------\n").c_str());
        printf(xorstr_("HANDLE: %p.\n").c_str(), hFile);
        printf(xorstr_("Buffer: %p.\n").c_str(), lpBuffer);
        printf(xorstr_("Size: %p.\n\n").c_str(), nNumberOfBytesToWrite);


        static int i = 0; // We increase that +=1 each for each dump


        std::wstring filePath = xorstr_(L"D:\\BEClient2_").c_str(); //Location to be saved the BEClient2.
        filePath.append(std::to_wstring(i) + xorstr_(L".dll").c_str());


        printf(xorstr_("[-] Opening handle to our file... \n").c_str());
        // Open a handle for saving
        auto* handleOurDump = CreateFile(filePath.c_str(),
                                         GENERIC_WRITE,
                                         0,
                                         nullptr,
                                         CREATE_NEW,
                                         FILE_ATTRIBUTE_NORMAL,
                                         nullptr);


        // Check if the handle was opened with sucess.
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf(xorstr_("[x] Failed top open the file for Writing... \n").c_str());
            i++;


            return orig_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
        }

        printf(xorstr_("[+] Handle Opened: %p\n").c_str(), handleOurDump);

        printf(xorstr_("[-] Saving %d bytes of (BEClient2) to: %ls\n").c_str(), nNumberOfBytesToWrite,
               filePath.c_str());


        // WriteFile file to our location
        if (orig_WriteFile(handleOurDump, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped))
        {
            printf(xorstr_("[+] Saved %d bytes successfully.\n").c_str(), *lpNumberOfBytesWritten);
        }
        else
        {
            //todo: GestLastError maybe?
            printf(xorstr_("[x] Failed to save the file \n").c_str());
        }

        printf(xorstr_("-------------------------------------------------------------\n\n").c_str());

        
        // Close our opened file.
        CloseHandle(handleOurDump);

        // To save the next file
        i++;

        // Save the file where be desired in the first place.
        return orig_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }


    return orig_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

bool WriteFileEx_Hk(
    HANDLE                          hFile,
    LPCVOID                         lpBuffer,
    DWORD                           nNumberOfBytesToWrite,
    LPOVERLAPPED                    lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    // Check if BE_StreamedHandle is not null, if its not, it means that be streamed the module, then, check if the current file to be save is the streamed module.
    if (BE_StreamedHandle != nullptr && hFile == BE_StreamedHandle)
    {
        printf(xorstr_("\n\n-----------[ Saving BEClient2 ] -----------\n").c_str());
        printf(xorstr_("HANDLE: %p.\n").c_str(), hFile);
        printf(xorstr_("Buffer: %p.\n").c_str(), lpBuffer);
        printf(xorstr_("Size: %p.\n\n").c_str(), nNumberOfBytesToWrite);


        static int b = 0; // We increase that +=1 each for each dump


        std::wstring filePath = xorstr_(L"D:\\BEClient2Ex_").c_str(); //Location to be saved the BEClient2.
        filePath.append(std::to_wstring(b) + xorstr_(L".dll").c_str());


        printf(xorstr_("[-] Opening handle to our file... \n").c_str());
        // Open a handle for saving
        auto* handleOurDump = CreateFile(filePath.c_str(),
                                         GENERIC_WRITE,
                                         0,
                                         nullptr,
                                         CREATE_NEW,
                                         FILE_ATTRIBUTE_NORMAL,
                                         nullptr);


        // Check if the handle was opened with sucess.
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf(xorstr_("[x] Failed top open the file for Writing... \n").c_str());
            b++;
            return orig_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
        }

        printf(xorstr_("[+] Handle Opened: %p\n").c_str(), handleOurDump);

        printf(xorstr_("[-] Saving %d bytes of (BEClient2) to: %ls\n").c_str(), nNumberOfBytesToWrite,
               filePath.c_str());


        DWORD lpNumberOfBytesWritten;

        // WriteFile file to our location
        if (orig_WriteFile(handleOurDump, lpBuffer, nNumberOfBytesToWrite, &lpNumberOfBytesWritten, lpOverlapped))
        {
            printf(xorstr_("[+] Saved %d bytes successfully.\n").c_str(), lpNumberOfBytesWritten);
        }
        else
        {
            //todo: GestLastError maybe?
            printf(xorstr_("[x] Failed to save the file \n").c_str());
        }

        printf(xorstr_("-------------------------------------------------------------\n\n").c_str());


        // Close our opened file.
        CloseHandle(handleOurDump);

        // To save the next file
        b++;

        // Save the file where be desired in the first place.
        return orig_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
    }


    return orig_WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
}


void HookStuff()
{
    AttachConsole();


    printf(xorstr_("------------------------------ STARTING HOOKING --------------------------------- \n\n\n").c_str());

    if (HookFunction((uintptr_t)CreateFileA, (uintptr_t)CreateFileA_Hk, (uintptr_t)&orig_CreateFileA))
        printf(xorstr_("[S] Hooked CreateFileA \n").c_str());
    else
        printf(xorstr_("[X] Failed CreateFileA \n").c_str());

    if (HookFunction((uintptr_t)CreateFileW, (uintptr_t)CreateFileW_Hk, (uintptr_t)&orig_CreateFileW))
        printf(xorstr_("[S] Hooked CreateFileW \n").c_str());
    else
        printf(xorstr_("[X] Failed CreateFileW \n").c_str());

    if (HookFunction((uintptr_t)WriteFile, (uintptr_t)WriteFile_Hk, (uintptr_t)&orig_WriteFile))
        printf(xorstr_("[S] Hooked WriteFile \n").c_str());
    else
        printf(xorstr_("[X] Failed WriteFile \n").c_str());

    if (HookFunction((uintptr_t)WriteFileEx, (uintptr_t)WriteFileEx_Hk, (uintptr_t)&orig_WriteFileEx))
        printf(xorstr_("[S] Hooked WriteFileEx \n").c_str());
    else
        printf(xorstr_("[X] Failed WriteFileEx \n").c_str());
}


HMODULE handler;

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD   ul_reason_for_call,
                      LPVOID  lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HookStuff();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
