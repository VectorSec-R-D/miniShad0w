#include "Api.h"

static HMODULE hKernel32 = NULL;
static LPVOID ptrGetProcAddress = NULL, ptrLoadLibraryA = NULL;

/*
	Простенький алгоритм хэширования
	Параметры:
	- str - строка, хэш которой нужно подсчитать
	- strSize - размер строки
*//*
static UINT CalcHash(char* str, size_t strSize)
{
	unsigned int hash = 0;
	if (str && strSize > 0)
	{
		for (size_t i = 0; i < strSize; i++, str++)
		{
			hash = (hash << 4) + *str;
			unsigned t;

			if ((t = hash & 0xf0000000) != 0)
			{
				hash = ((hash ^ (t >> 24)) & (0x0fffffff));
			}
		}
	}
	return hash;
}*/

// get ntdll handle without getmodulehandle
HMODULE resolveModuleBase(LPCWSTR module){

    UNKSTRUCT_t* mystruct;
    __asm
    {
        mov edx, dword ptr fs : [0x30]
        mov edx, [edx + 0x0C];
        mov edx, [edx + 0x14];
        mov[mystruct], edx;
    }
    while (mystruct->Name){

        if (mystrstr((LPWSTR)mystruct->Name, module)){
            return (HMODULE)mystruct->Base;
        }
        mystruct = (UNKSTRUCT_t*)mystruct->NextStruct;
    }

    return NULL;
}

/*
	Возвращает хэндл kernel32.dll
*/
HMODULE GetKernel32()
{
	__asm
	{
		mov eax, fs: [0x30]
		mov eax, [eax + 0xC]
		mov eax, [eax + 0xC]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x18]
	}
}

//added forwarded function
void* get_proc_address(HMODULE module, char* proc_name){
    char* modb = (char*)module;

	//printf("%s\n",proc_name);

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER *)modb;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS *)(modb + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER* opt_header = &nt_headers->OptionalHeader;
    IMAGE_DATA_DIRECTORY* exp_entry = (IMAGE_DATA_DIRECTORY *)
    (&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* exp_dir = (IMAGE_EXPORT_DIRECTORY *)(modb + exp_entry->VirtualAddress);
    
    void** func_table = (void **)(modb + exp_dir->AddressOfFunctions);
    WORD* ord_table = (WORD *)(modb + exp_dir->AddressOfNameOrdinals);
    char** name_table = (char **)(modb + exp_dir->AddressOfNames);
    void* address = NULL;
    DWORD i;
 
    /* is ordinal? */
    if (((DWORD)proc_name >> 16) == 0) {
        WORD ordinal = LOWORD(proc_name);
        DWORD ord_base = exp_dir->Base;

        /* is valid ordinal? */
        if (ordinal < ord_base || ordinal > ord_base + exp_dir->NumberOfFunctions){
            return NULL;
        }
        /* taking ordinal base into consideration */
        address = (void *)(modb + (DWORD)func_table[ordinal - ord_base]);
    }
    else {
        /* import by name */
        for (i = 0; i < exp_dir->NumberOfNames; i++){
            /* name table pointers are rvas */
            if (mystrcmp(proc_name, modb + (DWORD)name_table[i]) == 0){
                address = (void *)(modb + (DWORD)func_table[ord_table[i]]);
            }
        }
    }
    if ((char *)address >= (char *)exp_dir && (char *)address < (char *)exp_dir + exp_entry->Size) {
        char *dll_name, *func_name;
        HMODULE frwd_module;
        dll_name = mystrdup((char *)address);

        if (!dll_name){
            return NULL;
        }
        address = NULL;
        func_name = mystrchr(dll_name, '.');
        *func_name++ = 0;
 
        /* is already loaded? */
        frwd_module = resolveModuleBase((LPWSTR)dll_name);
        if (!frwd_module)
            frwd_module = ((T_LoadLibraryA)ptrLoadLibraryA)(dll_name);
 
        if (frwd_module)
            address = get_proc_address(frwd_module, func_name);
        hFree(dll_name);
    }
    return address;
}

/*
	Возвращает адрес функции из длл
	Параметры:
	- hModule - хэндл длл
	- funcHash - хэш имени функции 
*/
/*
static LPVOID GetApiAddr(HMODULE hModule, UINT funcHash)
{
	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)hModule;

	if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDOSHdr->e_lfanew);

	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE) return NULL;

	if ((pNTHdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == NULL || 
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL || 
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == NULL)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule +
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddress = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
	PDWORD pdwNames = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);
	PWORD pwOrd = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pIED->AddressOfFunctions; i++)
	{
		LPSTR pszFuncName = (LPSTR)((LPBYTE)hModule + pdwNames[i]);

		if (CalcHash(pszFuncName, mystrlen(pszFuncName)) == funcHash)
		{
			return (LPVOID)((LPBYTE)hModule + pdwAddress[pwOrd[i]]);
		}
	}

	return NULL;
}*/


/*
	Инициализация апи
*/
static void ApiInit(){
	if (!hKernel32){
		hKernel32 = GetKernel32();
	}

	/*if (!ptrGetProcAddress)
	{
		ptrGetProcAddress = (T_GetProcAddress)GetApiAddr(hKernel32, hashGetProcAddress);
	}*/

	if (!ptrLoadLibraryA)
	{
		//ptrLoadLibraryA = (T_LoadLibraryA)GetApiAddr(hKernel32, hashLoadLibraryA);
		XOR(C_LoadLibraryA, sizeof(C_LoadLibraryA)- 1, xorkey2);
		ptrLoadLibraryA = (T_LoadLibraryA)get_proc_address(hKernel32, C_LoadLibraryA);
		XOR(C_LoadLibraryA, sizeof(C_LoadLibraryA)- 1, xorkey2);
	}
}


static HMODULE DllHandls[12];

/*
	Возвращает адрес функции
	Параметры:
	- dll - номер длл
	- funcName - имя функции
*/
LPVOID GetWinAPI(int dll, LPSTR funcName, size_t funcSize){
	char dllName[20];
	LPVOID funcAddress = NULL;

	ApiInit();
	switch (dll){
	case KERNEL32:
		XOR(C_Kernel32dll, sizeof(C_Kernel32dll)- 1, xorkey);
		strCpyA(dllName, C_Kernel32dll);
		XOR(C_Kernel32dll, sizeof(C_Kernel32dll)- 1, xorkey);
		break;
	case USER32:
		XOR(C_User32dll, sizeof(C_User32dll)- 1, xorkey);
		strCpyA(dllName, C_User32dll);
		XOR(C_User32dll, sizeof(C_User32dll)- 1, xorkey);
		break;
	case SHELL32:
		XOR(C_Shell32dll, sizeof(C_Shell32dll)- 1, xorkey);
		strCpyA(dllName, C_Shell32dll);
		XOR(C_Shell32dll, sizeof(C_Shell32dll)- 1, xorkey);
		break;
	case OLE32:
		strCpyA(dllName, C_Ole32dll);
		break;
	case WININET:
		XOR(C_Wininetdll, sizeof(C_Wininetdll)- 1, xorkey);
		strCpyA(dllName, C_Wininetdll);
		XOR(C_Wininetdll, sizeof(C_Wininetdll)- 1, xorkey);
		break;
	case ADVAPI32:
		XOR(C_Advapi32dll, sizeof(C_Advapi32dll)- 1, xorkey);
		strCpyA(dllName, C_Advapi32dll);
		XOR(C_Advapi32dll, sizeof(C_Advapi32dll)- 1, xorkey);
		break;
	case WTSAPI32:
		XOR(C_Wtsapi32dll, sizeof(C_Wtsapi32dll)- 1, xorkey);
		strCpyA(dllName, C_Wtsapi32dll);
		XOR(C_Wtsapi32dll, sizeof(C_Wtsapi32dll)- 1, xorkey);
		break;
	case PSAPI:
		XOR(C_psapidll, sizeof(C_psapidll)- 1, xorkey);
		strCpyA(dllName, C_psapidll);
		XOR(C_psapidll, sizeof(C_psapidll)- 1, xorkey);
		break;
	default:
		return NULL;
	}

	HMODULE hDll = DllHandls[dll];
	if (!hDll){
		hDll = ((T_LoadLibraryA)ptrLoadLibraryA)(dllName);
		memoryset(dllName, 0, 20);
		DllHandls[dll] = hDll;
	}
	//return ((T_GetProcAddress)ptrGetProcAddress)(hDll, funcName);
	XOR(funcName, funcSize, xorkey2);
	funcAddress = get_proc_address(hDll, funcName);
	XOR(funcName, funcSize, xorkey2);
	return funcAddress;
}
