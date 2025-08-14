#ifndef PCH_HPP
#define PCH_HPP

#include <format>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>

#include <shellapi.h>
#include <winnt.h>

// mingw compilation hack
#if defined(__MINGW32__) || defined(__MINGW64__)
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct WTS_PROCESS_INFOW
    {
        DWORD SessionId;
        DWORD ProcessId;
        LPWSTR pProcessName;
        PSID pUserSid;
    } WTS_PROCESS_INFOW, *PWTS_PROCESS_INFOW;

#ifndef WTS_CURRENT_SERVER_HANDLE
#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)NULL)
#endif

    DECLSPEC_IMPORT BOOL WINAPI WTSEnumerateProcessesW(HANDLE, DWORD, DWORD, PWTS_PROCESS_INFOW *, PDWORD);
    DECLSPEC_IMPORT void WINAPI WTSFreeMemory(PVOID);

#ifdef __cplusplus
}
#endif
#else
#include <wtsapi32.h>
#endif

#endif // PCH_HPP
