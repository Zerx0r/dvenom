package cmd

import (
	"flag"
	"log"
	"os"
)

type Options struct {
	Lang       string
	MethodType string
	CipherType string
	Key        string
	ShellCode  []byte
	ProcName   string
}

func Parse() *Options {
	lang := flag.String("l", "", "Specify the language (Supported languages: cs, rust, ps1, aspx, vba).")
	methodType := flag.String("m", "", "Specify the method type (Supported types: valloc, pinject, hollow, ntinject).")
	cipherType := flag.String("e", "", "Specify the encryption type for the shellcode (Supported types: xor, rot, aes256, rc4).")
	key := flag.String("key", "", "Provide the encryption key.")
	path := flag.String("scfile", "", "Provide the path to the shellcode file.")
	procName := flag.String("procname", "explorer", "Provide the process name to be injected.")
	flag.Parse()

	if *lang != "cs" && *lang != "vba" && *lang != "aspx" && *lang != "ps1" && *lang != "rs" {
		log.Fatal("[x] Error: Invalid language. Please choose a supported language (cs, rs, ps1, aspx, vba).")
	}
	if *methodType != "valloc" && *methodType != "pinject" && *methodType != "hollow" && *methodType != "ntinject" {
		log.Fatal("[x] Error: Invalid method type. Please choose a supported method type (valloc, pinject, hollow, ntinject).")
	}
	if *cipherType != "xor" && *cipherType != "rot" && *cipherType != "aes256" && *cipherType != "rc4" {
		log.Fatal("[x] Error: Invalid cipher type. Please select a supported cipher for shellcode encryption (xor, rot, aes256, rc4).")
	}
	if *key == "" {
		log.Fatal("[x] Error: Encryption key is missing. Please provide the encryption key.")
	}
	if *path == "" {
		log.Fatal("[x] Error: Shellcode path file is missing. Please provide your shellcode path file.")
	}
	if *procName == "" && (*methodType == "pinject" || *methodType == "ntinject") {
		log.Fatal("[x] Error: Process name is missing. Please provide the name of the process to be injected by the shellcode.")
	}
	buf, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal("[x] Error: Shellcode provided is empty. Please double check your shellcode content.")
	}
	return &Options{Lang: *lang, MethodType: *methodType, CipherType: *cipherType, Key: *key, ShellCode: buf, ProcName: *procName}
}
