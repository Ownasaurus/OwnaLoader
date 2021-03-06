// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#include "targetver.h"
//#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <TLHELP32.H>
#include <shellapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <psapi.h>
// C++ RunTime Header Files
#include <list>
#include <string>
#define WM_TRAY (WM_USER + 1)
