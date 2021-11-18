package netpolicy

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"time"

	policy "github.com/containerd/containerd/api/services/auth/proto"
	"github.com/davecgh/go-spew/spew"
)

func newNetPolicyRequest(ak, sk string) *policy.FetchPolicyReq {
	token := signToken(sk, fmt.Sprintf("%s%d", "", time.Now().Unix()))
	return &policy.FetchPolicyReq{
		AccessKeyId: ak,
		Timestamp:   time.Now().Unix(),
		Signature:   token,
	}
}

func signToken(sk, data string) string {
	mac := hmac.New(md5.New, []byte(sk))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum([]byte("")))
}

func hashObject(object interface{}) string {
	hf := fnv.New32()
	printer := spew.ConfigState{
		Indent:         "",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	_, _ = printer.Fprintf(hf, "%#v", object)
	return fmt.Sprint(hf.Sum32())
}
