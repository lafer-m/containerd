package aesutil

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_aes(t *testing.T) {
	origin := "dawdawdljdwadwakdjwdwadjilwahidwahidwadwaqildiawdiliwadiqi"
	a, err := AesEncrypt([]byte(origin))
	if err != nil {
		t.Fatal(err)
	}
	o, _ := hex.DecodeString(a)
	b, err := AesDecrypt(o)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(a, b)
	if b != origin {
		t.Fatal()
	}
	fmt.Println(a, b)
}
