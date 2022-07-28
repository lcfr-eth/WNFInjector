package wnf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
	winapi "github.com/gonutz/w32/v2"
	my_winapi "github.com/lcfr-eth/WNFInjector/my_winapi"
	pefile "github.com/carbonblack/binee/pefile"
)

const (
	WNF_NODE_SUBSCRIPTION_TABLE  	= 0x911
	WNF_NODE_NAME_SUBSCRIPTION   	= 0x912
	WNF_NODE_SERIALIZATION_GROUP 	= 0x913
	WNF_NODE_USER_SUBSCRIPTION   	= 0x914
	WNF_STATE_KEY 			= 0x41C64E6DA3BC0074
)

type LIST_ENTRY struct {
	Flink 				uint64 //        LIST_ENTRY *Flink;
	Blink 				uint64 //        LIST_ENTRY *Blink;
}

type WNF_NAME_SUBSCRIPTION struct {
	Header				uint64 //uint64//uint32
	SubscriptionId			uint64
	StateName			uint64
	CurrentChangeStamp 		uint64
	NamesTableEntry			LIST_ENTRY //uint64 // LIST_ENTRY fixes the size. THIS FIXES SHIT BUT BREAKS SHIT LOLOLOL 
	TypeId				uint64
	SubscriptionLock 	    	uint64
	SubscriptionsListHead 	    	uint64 //
	NormalDeliverySubscriptions 	uint64
	NotificationTypeCount 		uint64
	RetryDescriptor 		uint64
	DeliveryState			uint64
	ReliableRetryTime 		uint64
}

type WNF_SUBSCRIPTION_TABLE struct {
        Header          		uint32 //WNF_CONTEXT_HEADER //WNF_CONTEXT_HEADER
        NamesTableLock  		uint64 // SRWLOCK sizeof pointer.. 8
        NamesTableEntry 		uint64
        SerializationGroupListHead 	uint64
        SerializationGroupLock 		uint64
        Unknown1                	uint32
        SubscribedEventSet      	uint32
        Unknown2                	uint32
        Timer                   	uint64
        TimerDueTime            	uint64
}

type WNF_CONTEXT_HEADER struct {
        NodeTypeCode    		uint16
        NodeByteSize    		uint16
}

type WNF_USER_SUBSCRIPTION struct {
	Header				uint32 //WNF_CONTEXT_HEADER
	SubscriptionsListEntry 		LIST_ENTRY//uint64 //LIST_ENTRY // uint64 // CHanging to LIST_ENTRY FROM uint64 fixed the struct size..
	NameSubscription		uint64 // this needs to be uint32 but breaks everything if changed from uint64 .. why
	Callback			uint32
	CallbackContext			uint64
	SubProcessTag 			uint64
	CurrentChangeStamp 		uint64
	DeliveryOptions 		uint64
	SubscribedEventSet 		uint64
	SerializationGroup 		uint64
	UserSubscriptionCount 		uint64
	Unknown 			uint64
}

func GetUserSubFromProcess() uintptr {

        var dos_h *pefile.DosHeader
        var cof_h *pefile.CoffHeader
        //var opt_h *pefile.OptionalHeader32P

        var wnf_ch *WNF_CONTEXT_HEADER
        var wnf_st *WNF_SUBSCRIPTION_TABLE
        var mi my_winapi.MEMORY_BASIC_INFORMATION

	var ptr_cnt int
	var idx int

	// load efswrt.dll to init the WNF structures in ntdll.
	syscall.LoadLibrary("efswrt.dll")

	// return the handle/pointer to ntdll.dll base in memory
        m := winapi.GetModuleHandle("ntdll.dll")
        fmt.Printf("[scan] Ntdll Base				: 0x%08X\n", m)

	// DosHeader of ntdll
	dos_h 	  = (*pefile.DosHeader)(unsafe.Pointer(m))
	//CoffHeader of ntdll
	cof_h 	  = (*pefile.CoffHeader)(unsafe.Pointer(uintptr(m) + uintptr(dos_h.AddressExeHeader) + 4))
	//OptionalHeader32P for x8664 // need to check if 32bit and compensate.. sections start after this address
	//opt_h 	  = (*pefile.OptionalHeader32P)(unsafe.Pointer(m + uintptr(dos_h.AddressExeHeader) + 4 + uintptr(binary.Size(pefile.CoffHeader{}))))

	Sections := make([]*pefile.SectionHeader, int(cof_h.NumberOfSections))

        //fmt.Printf("[pescan] DosHeader.e_lfanew          : 0x%08X\n",dos_h.AddressExeHeader)
	//fmt.Printf("[pescan] CoffHeader.Machine          : 0x%08X\n",cof_h.Machine)
	//fmt.Printf("[pescan] CoffHeader.NumberOfSections : %d    \n",cof_h.NumberOfSections)
	//fmt.Printf("[pescan] CoffHeader.ImageBase        : 0x%08X\n",opt_h.ImageBase)


	//SectionStart := uintptr(m + uintptr(dos_h.AddressExeHeader) + 4 + uintptr(binary.Size(pefile.CoffHeader{})) + uintptr(binary.Size(pefile.OptionalHeader32P{})))

	for i := 0; i < int(cof_h.NumberOfSections); i++ {
		//Sections[i] = (*pefile.Section)(unsafe.Pointer(SectionStart + uintptr(binary.Size(pefile.CoffHeader{}) * i)))
		if i == 0 {
			Sections[i] = (*pefile.SectionHeader)(unsafe.Pointer(uintptr(m) + uintptr(dos_h.AddressExeHeader) + 4 + uintptr(binary.Size(pefile.CoffHeader{})) + uintptr(binary.Size(pefile.OptionalHeader32P{}))))
		} else {
			Sections[i] = (*pefile.SectionHeader)(unsafe.Pointer(uintptr(m) + uintptr(dos_h.AddressExeHeader) + 4 + uintptr(binary.Size(pefile.CoffHeader{})) + uintptr(binary.Size(pefile.OptionalHeader32P{})) + uintptr(binary.Size(pefile.SectionHeader{}) * i)))
		}
	}

	for i := 0; i < int(cof_h.NumberOfSections); i++ {
		// refer to byte array as slice to be able to cast as a string.. idk, goshit.
		if(string(Sections[i].Name[:]) == ".data\x00\x00\x00") {
			fmt.Printf("[scan] .Data section found\n")
			idx = i
			break
		}
	}

        ptr_cnt = int(Sections[idx].VirtualSize) / my_winapi.PSIZE //8 change
        fmt.Printf("[scan] .Data VirtualAddress			: 0x%08X\n",uintptr(Sections[idx].VirtualAddress))

        ptr := uintptr(uintptr(m) + uintptr(Sections[idx].VirtualAddress))
        fmt.Printf("[scan] .Data VirtualAddress pointer 		: 0x%08X\n", ptr)

	for i := 0; i < ptr_cnt; i++ {

		wnf_st = (*WNF_SUBSCRIPTION_TABLE)(unsafe.Pointer(ptr))

		my_winapi.VirtualQuery(uintptr(wnf_st.Header) , &mi, int(unsafe.Sizeof(mi)))

		if ( (mi.State == uint32(my_winapi.MEM_COMMIT)) && (mi.Protect == uint32(my_winapi.PAGE_READWRITE) && (mi.Type == my_winapi.MEM_PRIVATE) )) {
			//fmt.Printf("check passed passed !!!\n")
		} else {
			ptr += uintptr(my_winapi.PSIZE)
			continue
		}
		///////////////////////////////////////////////////////////////////////
		wnf_ch = (*WNF_CONTEXT_HEADER)(unsafe.Pointer(uintptr(wnf_st.Header)))
		if (wnf_ch.NodeTypeCode == uint16(0x911)) {
			//fmt.Printf("[pescan] VirtualAddress of WNF Table : 0x%08X\n", uintptr(ptr))
			//fmt.Printf("[pescan] WNF_CONTEXT_HEADER	    : 0x%08X\n", uintptr(wnf_st.Header))
			//fmt.Printf("[pescan] FUCKING DONE\n")
			break
		}

		ptr += uintptr(my_winapi.PSIZE)
	}

      //ReadProcessMemory here
      //err = wrappers.ReadProcessMemory(hProcess, basicInfo.PebBaseAddress, (*byte)(unsafe.Pointer(&peb)), uint32(unsafe.Sizeof(peb)), nil)

	return ptr
}

func GetUserSubFromTable(handle my_winapi.HANDLE, addr uintptr) (uint64, WNF_USER_SUBSCRIPTION) {
	//var st *WNF_SUBSCRIPTION_TABLE //
	var t 	[]byte

	var sa 	uint64
	var us 	WNF_USER_SUBSCRIPTION
	var ns  WNF_NAME_SUBSCRIPTION
	var l    LIST_ENTRY
	var nsle LIST_ENTRY

	///////////////////////////////
	tbl 	:= addr
	//////////////////////////////

	//buf := &bytes.Buffer{}
	//#define WNF_SHEL_LOGON_COMPLETE            0xd83063ea3bc1875
	const WNF_SHEL_LOGON_COMPLETE = 0xd83063ea3bc1875

	t, err := my_winapi.ReadProcessMemory(handle, uintptr(tbl), uint(my_winapi.PSIZE))
        if err != nil {
                fmt.Printf("- ReadProcessMemory Error")
        }
	// convert byte array to int using binary.BigEndian.Uint32()
	fmt.Printf("[scan] WNF_SUBSCRIPTION_TABLE.NamesTableEntry	: 0x%08X ->  0x%08X\n", tbl, binary.LittleEndian.Uint32(t))

	/*
        ReadProcessMemory(hp, (PBYTE)addr + offsetof(WNF_SUBSCRIPTION_TABLE, NamesTableEntry), &stle, sizeof(stle), &rd);
        */

	n := binary.LittleEndian.Uint32(t)
	//fmt.Printf("offset of our struct.. 0x%08X\n", unsafe.Offsetof(st.NamesTableEntry)) // THIS IS RIGHT .. 0x10
	n = n + 0x10 // distance from offset 0 to the NamesTableEntry member
	t, err = my_winapi.ReadProcessMemory(handle, uintptr(n), uint(unsafe.Sizeof(l))) //was uint(8)  sizeof(LIST_ENTRY) // sizeof(stle)
        binary.Read(bytes.NewBuffer(t[:]), binary.LittleEndian, &l) // populate list struct

	fmt.Printf("[scan] WNF_NAME_SUBSCRIPTION List		: 0x%08X ->  0x%08X\n", n, l.Flink) //binary.LittleEndian.Uint32(t))

	nte := l.Flink
      	for {
		p := (uint64(nte) - uint64(unsafe.Offsetof(ns.NamesTableEntry)))

		t, err = my_winapi.ReadProcessMemory(handle, uintptr(p), uint(unsafe.Sizeof(ns))) // sizeof(WNF_NAME_SUBSCRIPTION)
        	binary.Read(bytes.NewBuffer(t[:]), binary.LittleEndian, &ns) // populate list struct

                if (ns.StateName == 0xd83063ea3bc1875) {

			use := ns.SubscriptionsListHead
			sa := (use - uint64(unsafe.Offsetof(us.SubscriptionsListEntry)))
			t, err = my_winapi.ReadProcessMemory(handle, uintptr(sa), uint(unsafe.Sizeof(us)))
			binary.Read(bytes.NewBuffer(t[:]), binary.LittleEndian, &us) // populate struct
			return sa, us
                }

		// last in linked list?
		if (nte == l.Blink) {
			break
		}

		t, err = my_winapi.ReadProcessMemory(handle, uintptr(nte), uint(unsafe.Sizeof(nsle))) // sizeof(WNF_NAME_SUBSCRIPTION)
		binary.Read(bytes.NewBuffer(t[:]), binary.LittleEndian, &nsle) // populate list struct
		nte = nsle.Flink

        }
	return sa, us
}
