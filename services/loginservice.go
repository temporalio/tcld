package services

import (
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
)

type loginService struct {
}

type LoginService interface {
	OpenBrowser(URL string) error
	WriteToConfigFile(configPath string, data string) error
	DeleteConfigFile(configPath string) error
}

func NewLoginService() LoginService {
	return &loginService{}
}

func (c *loginService) OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("xdg-open", url).Start(); err != nil {
			return err
		}
	case "windows":
		if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
			return err
		}
	case "darwin":
		if err := exec.Command("open", url).Start(); err != nil {
			return err
		}
	default:
	}
	return nil
}

func (c *loginService) WriteToConfigFile(configPath string, data string) error {
	// Write file as 0600 since it contains private keys.
	return ioutil.WriteFile(configPath, []byte(data), 0600)
}

func (c *loginService) DeleteConfigFile(configPath string) error {
	if _, err := os.Stat(configPath); err == nil {
		return os.RemoveAll(configPath)
	}
	return nil
}

func (c *loginService) DeleteConfigFile(configPath string) error {
	if _, err := os.Stat(configPath); err == nil {
		return os.RemoveAll(configPath)
	}
	return nil
}
