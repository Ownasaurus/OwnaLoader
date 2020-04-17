// OwnaLoader2020.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "OwnaLoader2020.h"

// Global Variables:
HWND hWnd;

PROCESSENTRY32 PE32;
NOTIFYICONDATA data;
TCHAR szTarget[] = _T("game.exe"); // <-- change this if you want to use the loader with another game!
TCHAR szPath[MAX_PATH], szDllToInject[MAX_PATH];

std::list<DWORD> aulInjectedPIDs;

void Fail(LPCTSTR message)
{
	MessageBox(NULL, message, _T("Error!"), MB_ICONERROR | MB_OK);
}

DWORD WINAPI InjectionThread(LPVOID lpParam)
{
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hKernel32;
	LPVOID lpRemoteString = NULL;
	FARPROC lpLoadLibraryA;
	PE32.dwSize = sizeof(PROCESSENTRY32);

	while (true)
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
					hKernel32 = GetModuleHandle(_T("kernel32"));
					if (hKernel32)
					{
						lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
						if (lpLoadLibraryA)
						{
							hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PE32.th32ProcessID);
							if (hProcess)
							{
								lpRemoteString = VirtualAllocEx(hProcess, 0, sizeof(szDllToInject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

								if (lpRemoteString)
								{
									WriteProcessMemory(hProcess, lpRemoteString, (LPVOID)szDllToInject, sizeof(szDllToInject), NULL);
									hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibraryA), lpRemoteString, 0, NULL);
									WaitForSingleObject(hThread, INFINITE);
									VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);
									CloseHandle(hProcess);
									CloseHandle(hThread);

									aulInjectedPIDs.push_back(PE32.th32ProcessID); // add to our list of injected PIDs
								}
								else
								{
									Fail(_T("VirtualAllocEx failed during inject!"));
									CloseHandle(hProcess);
									return 1;
								}
							}
							else
							{
								Fail(_T("OpenProcess failed during inject!"));
								return 1;
							}
						}
						else
						{
							Fail(_T("GetProcAddress failed during inject!"));
							return 1;
						}
					}
					else
					{
						Fail(_T("GetModuleHandle failed during inject!"));
						return 1;
					}
				}

				if (GetAsyncKeyState(VK_F11) & 1) // Abort key! Un-inject everything!
				{
					hKernel32 = GetModuleHandle(_T("kernel32"));
					if (hKernel32)
					{
						FARPROC lpFreeLibraryA = GetProcAddress(hKernel32, "FreeLibraryA");
						if (lpFreeLibraryA)
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
										hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpFreeLibraryA), lpRemoteString, 0, NULL);
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
				}
			}
		}
		while (Process32Next(hSnapshot, &PE32));

		CloseHandle(hSnapshot);
	}

	return 0;
}

void TrayProc(WPARAM wParam, LPARAM lParam)
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
    TCHAR szMessage[] = _T("Click here to restore the window.");
    data.cbSize = sizeof(NOTIFYICONDATA);
    data.hIcon = LoadIcon(hInstance, (PTCHAR)IDC_MYICON);
    data.uCallbackMessage = WM_TRAY;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_INFO;
    data.uID = 1;
    _stprintf_s(data.szInfo, szMessage);
    _stprintf_s(data.szInfoTitle, _T("All your base are belong to us!"));
    data.dwInfoFlags = NIIF_INFO;

	DWORD dwParam1, dwThreadID1;
	// This thread constantly searches for processes to inject
    CreateThread(NULL, 0, InjectionThread, &dwParam1, 0, &dwThreadID1);

	// This interface pretty much just serves to provide the user with an option to exit the program
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), hWnd, (DLGPROC)MainDlgProc);

    return 0;
}
