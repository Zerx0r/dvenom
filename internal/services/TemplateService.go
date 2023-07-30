package services

import (
	"github.com/Zerx0r/dvenom/cmd"
	"github.com/Zerx0r/dvenom/internal/payloads"
)

type ITemplateService interface {
	GetCSharp() string
	GetRust() string
	GetPwsh() string
	GetAspx() string
	GetVBAMacro() string
}

type templateService struct {
	options *cmd.Options
}

func NewTemplateService(options *cmd.Options) ITemplateService {
	return &templateService{
		options: options,
	}
}

func (t *templateService) GetCSharp() string {
	return payloads.BuildCsharpTemplate(t.options.MethodType, t.options.CipherType, t.options.Key, t.options.ProcName, t.options.ShellCode)
}
func (t *templateService) GetRust() string {
	return payloads.BuildRustTemplate(t.options.MethodType, t.options.CipherType, t.options.Key, t.options.ProcName, t.options.ShellCode)
}
func (t *templateService) GetPwsh() string {
	return payloads.BuildPwshTemplate(t.options.MethodType, t.options.CipherType, t.options.Key, t.options.ProcName, t.options.ShellCode)
}
func (t *templateService) GetAspx() string {

	return payloads.BuildAspxTemplate(t.options.MethodType, t.options.CipherType, t.options.Key, t.options.ShellCode)
}
func (t *templateService) GetVBAMacro() string {
	return payloads.BuildVBATemplate(t.options.MethodType, t.options.CipherType, t.options.Key, t.options.ShellCode)
}
