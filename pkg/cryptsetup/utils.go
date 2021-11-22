package cryptsetup

import (
	"fmt"
	"io/ioutil"
	"os"
)

func StoreCryptState(path, crypt string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s", crypt)
	return err
}

func LoadCryptState(path string) (string, error) {
	cy, err := ioutil.ReadFile(path)
	return string(cy), err
}
