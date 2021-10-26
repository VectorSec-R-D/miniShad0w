#include "main.h"

char* mystrstr (const char * str1, const char * str2){
    char* cp = (char *)str1;
    char* s1;
    char* s2;

    if ( !*str2 ){
        return((char *)str1);
    }
    while (*cp){
        s1 = cp;
        s2 = (char *) str2;
        while ( *s2 && !(*s1 - *s2) ){
            s1++, s2++;
        }
        if (!*s2){
            return(cp);
        }
        cp++;
    }
    return(NULL);
}

char* strCpyA(char* dest, const char* src){
    char* wcp = dest - 1;
    wint_t c;
    const ptrdiff_t off = src - dest + 1;
    do{
        c = wcp[off];
        *++wcp = c;
    } while (c != '\0');
    return wcp;
}

int mystrcmp(const char *s1, const char* s2){
	int i;

    for (i = 0; s1[i] && s2[i]; ++i){
        if (s1[i] == s2[i] || (s1[i] ^ 32) == s2[i]){
           continue;
        }
        else{
           break;
        }
    }
    if (s1[i] == s2[i]){
        return 0;
    }
    if ((s1[i] | 32) < (s2[i] | 32)){ 
        return -1;
    }
    return 1;
}

#pragma optimize("", off)
void memoryset(void* dest, int val, size_t len){
    register unsigned char* s = (unsigned char*)dest;

    while (len-- > 0){
        *s++ = val;
    }  
}

void mymemcpy(char* dest, const char* src, unsigned int len){

    while (len-- > 0){
        *dest++ = *src++;
    }
}

extern inline char* mystrchr (register const char *s, int c){
  do {
    if (*s == (char)c){ //char holds ascii valuesm only lower 8bits are compares thus prototype
        return (char*)s;
    }
  } while (*s++); //*s++  add  one to the pointer value
  return (0);
}

/*
void *myrealloc(void *ptr, size_t newSize)
{   
    RtlAllocateHeap_ RtlAllocateHeap = (RtlAllocateHeap_)get_proc_address(resolveModuleBase(L"ntdll.dll"), "RtlAllocateHeap");
    GetProcessHeap_ GetProcessHeap = (GetProcessHeap_)get_proc_address(resolveModuleBase(L"KERNEL32.dll"), "GetProcessHeap");

    void *newPtr;

    if (ptr == 0) {
		return RtlAllocateHeap(GetProcessHeap(), 0x00000001 | 0x00000008 ,newSize);
    }
    newPtr = RtlAllocateHeap(GetProcessHeap(), 0x00000001 | 0x00000008 ,newSize);
    mymemcpy(newPtr, ptr, (int) mystrlen(ptr)+1);

    RtlFreeHeap_ RtlFreeHeap = (RtlFreeHeap_)get_proc_address(resolveModuleBase(L"ntdll.dll"), "RtlFreeHeap");
    RtlFreeHeap(GetProcessHeap(), 0, ptr);
    return(newPtr);
}*/

void XOR(char* data, size_t data_len, char* key){
    int i;
    //decrypting master key
    for(i = 0; i < 27; i++){
        key[i] = key[i] ^ masterkey[i % 27];
    }

    //decryting main data
    for(i = 0; i < data_len; i++){
        data[i] = data[i] ^ key[i % 27];
    }

    //encrypt the key again
    for(i = 0; i < 27; i++){
        key[i] = key[i] ^ masterkey[i % 27];
    }
}

char* split(char* src){
    char* buf = hAlloc(100);
    int bufsize = 100;
    char* cp = buf;

    while(*src != '|'){
        if(bufsize < 1){
            break;
        }
        *cp++ = *src++;
         bufsize--;
    }
    *cp = '\0';
    return buf;
}

size_t mystrlen(const char* str) {
    register const char* s;
    for (s = str; *s; ++s);
    return(s - str);
}

extern inline size_t mywcslen(const WCHAR* ws){
    const WCHAR* eows = ws;
    while(* eows != 0){
        ++eows;
    }
    return (eows - ws);
}

/* Duplicate S, returning an identical malloc'd string.  */
char * mystrdup (const char *s)
{
  size_t len = mystrlen (s) + 1;
  void *new = hAlloc (len);
  if (new == NULL){
    return NULL;
  }
  mymemcpy (new, s, len);
  return (char*)new;
}

HANDLE GetHeap()
{
    __asm
    {
        mov eax, fs: [0x30]
        mov eax, [eax + 0x18]
    }
}

void* hAlloc(size_t Size){

    XOR(C_RtlAllocateHeap, sizeof (C_RtlAllocateHeap)-1, xorkey2);  
    RtlAllocateHeap_ RtlAllocateHeap = (RtlAllocateHeap_)get_proc_address(resolveModuleBase(L"ntdll.dll"), C_RtlAllocateHeap);
    XOR(C_RtlAllocateHeap, sizeof(C_RtlAllocateHeap)-1, xorkey2);

    return RtlAllocateHeap(GetHeap(), 0x00000008, Size);
    //return malloc(size);
    //return API(KERNEL32, HeapAlloc)(GetHeap(), 0x00000008, size);
}

void hFree(void* mem){

    XOR(C_RtlFreeHeap, sizeof(C_RtlFreeHeap)-1, xorkey2);
    RtlFreeHeap_ RtlFreeHeap = (RtlFreeHeap_)get_proc_address(resolveModuleBase(L"ntdll.dll"), C_RtlFreeHeap);
    XOR(C_RtlFreeHeap, sizeof(C_RtlFreeHeap)-1, xorkey2);

    if (mem) {
        RtlFreeHeap(GetHeap(), 0, mem);  
    }
    // if (mem) free(mem);
   //if (mem) API(KERNEL32, HeapFree)(GetHeap(), 0, mem);
}
