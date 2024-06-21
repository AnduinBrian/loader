// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#define     CRC_POLYNOMIAL      0xEDB88320
#define     STR                 "_CRC32"

CONST CHAR* g_StringsArray[] = {
    // Syscalls
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtProtectVirtualMemory",
    "NtUnmapViewOfSection",
    "NtAllocateVirtualMemory",
    "NtDelayExecution",

    // Used in GetProcAddressH
    "LoadLibraryA",
    
    // Used for payload execution
    "CreateThreadpoolTimer",
    "SetThreadpoolTimer",
    "WaitForSingleObject",
    
    // Used in the unhooking routine
    "AddVectoredExceptionHandler",
    "RemoveVectoredExceptionHandler",
	
    NULL
};


UINT32 CRC32B (LPCSTR cString) {

    UINT32      uMask   = 0x00,
                uHash   = 0xFFFFFFFF;
    INT         i       = 0x00;

    while (cString[i] != 0) {
        
        uHash = uHash ^ (UINT32)cString[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & uMask);
        }

        i++;
    }

    return ~uHash;
}


#define CRCHASH(STR)    ( CRC32B( (LPCSTR)STR ) )


int main() {

    DWORD ii = 0;

    while (g_StringsArray[ii]){
        printf("#define %s%s \t 0x%0.8X \n", g_StringsArray[ii], STR, CRCHASH(g_StringsArray[ii]));
        ii++;
    }

    // Used in UnhookAllLoadedDlls
    printf("\n#define %s%s \t 0x%0.8X \n", "text", STR, CRCHASH(".text"));

    // Used in FetchWin32uSyscallInst
    printf("#define %s%s \t 0x%0.8X \n", "win32udll", STR, CRCHASH("win32u.dll"));

    // Used with GetModuleHandleH
    printf("\n#define %s%s \t 0x%0.8X \n", "kernel32dll", STR, CRCHASH("kernel32.dll"));
    printf("#define %s%s \t 0x%0.8X \n", "ntdlldll", STR, CRCHASH("ntdll.dll"));

}
