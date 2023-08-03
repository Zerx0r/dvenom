package main

import (
	"fmt"

	"github.com/Zerx0r/dvenom/cmd"
	"github.com/Zerx0r/dvenom/internal/services"
)

func main() {
	options := cmd.Parse()
	service := services.NewTemplateService(options)
	switch options.Lang {
	case "cs":
		fmt.Println(service.GetCSharp())
	case "rs":
		fmt.Println(service.GetRust())
	case "vba":
		fmt.Println(service.GetVBAMacro())
	case "aspx":
		fmt.Println(service.GetAspx())
	case "ps1":
		fmt.Println(service.GetPwsh())
	}
}
