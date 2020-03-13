# author: size_t

# import the required module to handle Windows API Calls
import ctypes

#import python ->Windows types from ctypes
from ctypes.wintypes import DWORD,LPWSTR,WORD,LPBYTE,HANDLE

#getting a handle to kernel32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")

# structure for startup info 
class STARTUPINFO(ctypes.Structure):
	_fields_ = [
	("cb", DWORD),
	("lpReserved", LPWSTR),
	("lpDesktop", LPWSTR),
	("lpTitle", LPWSTR),
	("dwX", DWORD),
	("dxY", DWORD),
	("dwXSize", DWORD),
	("dwYSize", DWORD),
	("dwXCountChars", DWORD),
	("dwYCountChars", DWORD),
	("dwFillAttribute", DWORD),
	("dwFlags", DWORD),
	("wShowWindow", WORD),
	("cbReserved2", WORD),
	("lpReserved2", LPBYTE),
	("hStdInput", HANDLE),
	("hStdOutput", HANDLE),
	("hStdError", HANDLE),
	]


# structure for process info
class PROCESS_INFORMATION(ctypes.Structure):
	_fields_ = [
		("hprocess", HANDLE),
		("hthread", HANDLE),
		("dwProcessID", DWORD),
		("dwThreadId", DWORD),
		]

# setup the parameters for the Win API calls		
lpApplicationName = "c:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
lpEnvironment = None
lpCurrentDirectory = None

# setup creation flags
# CREATE_NEW_CONSOLE option
dwCreationFlags = 0x00000010

# setup inherit handle 
# I set this to false because we don't want to inherit the handle into our current process
bInheritHandle = False

# create empty copy of PROCESS_INFORMATION so the data can be saved to items
lpProcessInformation = PROCESS_INFORMATION()

# create startup info struct
lpStartupInfo = STARTUPINFO()

# set the window to show
lpStartupInfo.wShowWindow = 0x1

# setup flags
# 0x1 is STARTF_USESHOWWINDOW - tells window to check wShowWindow flag in startup info
lpStartupInfo.dwFlags = 0x1 

# get the size of the structure after settings are set
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)


# running the API call
response = k_handle.CreateProcessW(
	lpApplicationName,
	lpCommandLine,
	lpProcessAttributes,
	lpThreadAttributes,
	bInheritHandle,
	dwCreationFlags,
	lpEnvironment,
	lpCurrentDirectory,
	ctypes.byref(lpStartupInfo),
	ctypes.byref(lpProcessInformation))

# handling any errors
if response > 0:
	print("[INFO] Process is created and running. . .")
else:
	print("[ERROR] Failed, could not create process! Error Code: {0}".format(k_handle.GetLastError()))
