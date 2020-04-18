/* RemoteOps.h */
// https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded

#ifndef REM_OPS_H
#define REM_OPS_H

HMODULE WINAPI GetRemoteModuleHandle(HANDLE hProcess, LPCSTR lpModuleName);
FARPROC WINAPI GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName, UINT Ordinal = 0, BOOL UseOrdinal = FALSE);

#endif //REM_OPS_H