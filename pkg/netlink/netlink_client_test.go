package netlink

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

const (
	stamp = "WEARETHEBEST"
	charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func RandString(length int) string {
	source := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[source.Int63()%int64(len(charset))]
	}
	return string(b)
}


func TestNetlinkClient(t *testing.T) {
	cfg := &DACSNetlinkCfg{
		KernelStamp:stamp,
		NetlinkProto:19,
	}

	na, err := NewDACSNetlinkClient(cfg)
	if err != nil {
		t.Fatalf("new dacs netlink client failed: %s", err)
	}

	err = na.SetMasterProInfo(56789)
	if err != nil {
		t.Fatalf("SetMasterProInfo failed, err: %s", err)
	}

	sandboxId1 := RandString(128)
	err = na.AddSandbox(sandboxId1, 1234, "/root/testdir/")
	fmt.Printf("SandboxID = %s\n" , sandboxId1)
	if err != nil {
		t.Fatalf("AddSandbox failed, err: %s", err)
	}

	sandboxId2 := RandString(128)
	err = na.AddSandbox(sandboxId2, 12345, "/root/testdir/")
	fmt.Printf("SandboxID = %s\n" , sandboxId2)
	if err != nil {
		t.Fatalf("AddSandbox failed, err: %s", err)
	}

	err = na.RemoveSandbox(sandboxId1)
	err = na.RemoveSandbox(sandboxId2)
}

