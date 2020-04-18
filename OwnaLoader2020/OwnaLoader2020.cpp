// OwnaLoader2020.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "OwnaLoader2020.h"

// Global Variables:
HWND hWnd;

PROCESSENTRY32 PE32;
NOTIFYICONDATA data;
TCHAR szTarget[] = _T("Game.exe"); // <-- change this if you want to use the loader with another game!
TCHAR szPath[MAX_PATH], szDllToInject[MAX_PATH];

std::list<DWORD> aulInjectedPIDs;

VOID Fail(LPCTSTR message)
{
	TCHAR buf[256];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (sizeof(buf) / sizeof(TCHAR)), NULL);
	MessageBox(NULL, buf, _T("Error!"), MB_ICONERROR | MB_OK);
	MessageBox(NULL, message, _T("Error!"), MB_ICONERROR | MB_OK);

	ExitProcess(1);
}

// Source: https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL EnableDebugPrivledges()
{
	HANDLE hToken;
	BOOL success = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		success = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	}

	CloseHandle(hToken);

	return success;
}

DWORD WINAPI InjectionThread(LPVOID lpParam)
{
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hKernel32;
	LPVOID lpRemoteString = NULL;
	FARPROC lpLoadLibraryW;
	PE32.dwSize = sizeof(PROCESSENTRY32);

	BOOL bOurArch = FALSE;
	if (!IsWow64Process(GetCurrentProcess(), &bOurArch))
	{
		Fail(_T("IsWow64Process failed before inject!"));
		return 1;
	}

	while (TRUE)
	{
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		Process32First(hSnapshot, &PE32);

		do
		{
			Sleep(10);

			if (_tcscmp(PE32.szExeFile, szTarget) == 0)
			{
				std::list<DWORD>::iterator end = aulInjectedPIDs.end();
				std::list<DWORD>::iterator it = std::find(aulInjectedPIDs.begin(), end, PE32.th32ProcessID);
				if (it == end) // if not already injected, inject it!
				{
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, PE32.th32ProcessID);
					if (!hProcess)
					{
						Fail(_T("OpenProcess failed during inject!"));
					}

					BOOL bRemoteArch = FALSE;
					if (!IsWow64Process(hProcess, &bRemoteArch))
					{
						Fail(_T("IsWow64Process failed during inject!"));
					}

					if (bOurArch != bRemoteArch)
					{
						if (bOurArch)
						{
							MessageBox(NULL, _T("This 32-bit injector should not be used to inject into a 64-bit process!"), _T("Error!"), MB_ICONERROR | MB_OK);
						}
						else
						{
							MessageBox(NULL, _T("This 64-bit injector should not be used to inject into a 32-bit process!"), _T("Error!"), MB_ICONERROR | MB_OK);
						}
						ExitProcess(1);
					}

					hKernel32 = GetModuleHandle(_T("kernel32"));
					if (!hKernel32)
					{
						Fail(_T("GetModuleHandle failed during inject!"));
					}

					lpLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
					if (!lpLoadLibraryW)
					{
						Fail(_T("GetProcAddress failed during inject!"));
					}

					lpRemoteString = VirtualAllocEx(hProcess, 0, sizeof(szDllToInject), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					if (!lpRemoteString)
					{
						CloseHandle(hProcess);
						Fail(_T("VirtualAllocEx failed during inject!"));
					}

					WriteProcessMemory(hProcess, lpRemoteString, (LPVOID)szDllToInject, sizeof(szDllToInject), NULL);
					hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibraryW), lpRemoteString, 0, NULL);
					WaitForSingleObject(hThread, INFINITE);
					DWORD exitCode;
					if (!GetExitCodeThread(hThread, &exitCode))
					{
						Fail(_T("Could not get exit code of remote thread !"));
					}
					if (!exitCode)
					{
						MessageBox(NULL, _T("Remote LoadLibraryW returned a NULL handle!"), _T("Error!"), MB_ICONERROR | MB_OK);
						ExitProcess(1);
					}
					VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE); // get rid of our temporary string text
					CloseHandle(hProcess);
					CloseHandle(hThread);

					//TODO: store the exitCode (which is a handle) AND PID as a tuple in the list.
					aulInjectedPIDs.push_back(PE32.th32ProcessID); // add to our list of injected PIDs
				}

				//TODO: FreeLibrary with the handle to the result of the remote loadlibrary
				/*if (GetAsyncKeyState(VK_F11) & 1) // Abort key! Un-inject everything!
				{
					hKernel32 = GetModuleHandle(_T("kernel32"));
					if (hKernel32)
					{
						FARPROC lpFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");
						if (lpFreeLibrary)
						{
							while(!aulInjectedPIDs.empty())
							{
								hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, aulInjectedPIDs.front());
								if (hProcess)
								{
									lpRemoteString = VirtualAllocEx(hProcess, 0, sizeof(szDllToInject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

									if (lpRemoteString)
									{
										WriteProcessMemory(hProcess, lpRemoteString, (LPVOID)szDllToInject, sizeof(szDllToInject), NULL);
										hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpFreeLibrary), lpRemoteString, 0, NULL);
										WaitForSingleObject(hThread, INFINITE);
										VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);
										CloseHandle(hProcess);
										CloseHandle(hThread);
									}
									else
									{
										Fail(_T("VirtualAllocEx failed during un-inject!"));
										CloseHandle(hProcess);
										return 1;
									}
								}
								// Don't worry if hProcess is NULL, because the process might no longer exist. Just keep on going

								aulInjectedPIDs.pop_front();
							}
						}
						else
						{
							Fail(_T("GetProcAddress failed during un-inject!"));
							return 1;
						}
					}
					else
					{
						Fail(_T("GetModuleHandle failed during un-inject!"));
						return 1;
					}
				}*/
			}
		}
		while (Process32Next(hSnapshot, &PE32));

		CloseHandle(hSnapshot);
	}

	return 0;
}

VOID TrayProc(WPARAM wParam, LPARAM lParam)
{
	if ((UINT)lParam == WM_LBUTTONDOWN)
	{
		Shell_NotifyIcon(NIM_DELETE, &data);
		ShowWindow((HWND)wParam, SW_SHOW);
	}
}

LRESULT CALLBACK MainDlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	case WM_SYSCOMMAND:
		if (wParam == SC_MINIMIZE)
		{
			data.hWnd = hDlg;

			Shell_NotifyIcon(NIM_ADD, &data);

			ShowWindow(hDlg, SW_HIDE);
			return TRUE;
		}
		break;
	case WM_TRAY:
		TrayProc((WPARAM)(hDlg), lParam);
		break;
	}

	return FALSE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	// Get debug privledges so we can OpenProcess other processes
	if (!EnableDebugPrivledges())
	{
		MessageBox(NULL, _T("Could not acquire sufficient privledges for injection.\nPlease run as administrator."), _T("Doh"), NULL);
		return 1;
	}

    // Load szDllToInject with the path of the DLL to be injected, determined based on the filename of this program
    // just replace ".exe" with ".dll".
    GetModuleFileName(0, szPath, sizeof(szPath));
    _tcscpy_s(szDllToInject, szPath);
    SIZE_T cbPathLength = _tcslen(szPath);
    szDllToInject[cbPathLength - 3] = _T('d');
    szDllToInject[cbPathLength - 2] = _T('l');
    szDllToInject[cbPathLength - 1] = _T('l');

    // Find the .dll and make sure it exists. Otherwise notify and exit.
    WIN32_FIND_DATA fnd;
    HANDLE DllHnd = FindFirstFile(szDllToInject, &fnd);
    if (DllHnd == INVALID_HANDLE_VALUE)
    {
        TCHAR szFailMsg[512] = { 0 };
        _stprintf_s(szFailMsg, _T("The library to be injected could not be found:\n\n\"%s\""), szDllToInject);
		Fail(szFailMsg);
        return 1;
    }

	// Set tray icon data
    data.cbSize = sizeof(NOTIFYICONDATA);
    data.hIcon = LoadIcon(hInstance, (PTCHAR)IDI_ICON1);
    data.uCallbackMessage = WM_TRAY;
    data.uFlags = NIF_MESSAGE | NIF_ICON;
    data.uID = 1;
    data.dwInfoFlags = NIIF_INFO;

	DWORD dwParam1, dwThreadID1;
	// This thread constantly searches for processes to inject
    CreateThread(NULL, 0, InjectionThread, &dwParam1, 0, &dwThreadID1);

	// This interface pretty much just serves to provide the user with an option to exit the program
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), hWnd, (DLGPROC)MainDlgProc);

    return 0;
}
