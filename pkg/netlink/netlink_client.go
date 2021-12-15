package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type DACSNlMsg struct {
	nlhdr   syscall.NlMsghdr
	data    []byte
	dataLen int
}

type DACSNetLink struct {
	proto    int
	nlFd     int
	sockaddr syscall.SockaddrNetlink
}

func DACSNlMsgInit(data []byte) *DACSNlMsg {
	dmsg := DACSNlMsg{
		nlhdr: syscall.NlMsghdr{
			Len:   uint32((syscall.SizeofNlMsghdr) + len(data)),
			Type:  0,
			Flags: 0,
			Seq:   0,
			Pid:   uint32(os.Getpid()),
		},
		data:    data,
		dataLen: len(data),
	}

	return &dmsg
}

func (nlm *DACSNlMsg) Serialize() ([]byte, int) {
	buffer := make([]byte, nlm.nlhdr.Len)

	hds := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(&(nlm.nlhdr))))[:]

	start := 0
	stop := syscall.SizeofNlMsghdr
	copy(buffer[start:stop], hds)

	start = stop
	stop = start + nlm.dataLen
	copy(buffer[start:stop], nlm.data)

	return buffer, stop + 1
}

// func DACSNetLinkInit(proto int, handler ReciveHandler) *DACSNetLink {
func DACSNetLinkInit(proto int) *DACSNetLink {
	return &DACSNetLink{
		proto: proto,
		//recvhandler: handler,
		sockaddr: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Pad:    0,
			Pid:    uint32(os.Getpid()),
			Groups: 0,
		},
	}
}

func (nl *DACSNetLink) BindPID() error {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, nl.proto)
	if e != nil {
		return e
	}

	nl.nlFd = fd
	e = syscall.Bind(nl.nlFd, &(nl.sockaddr))
	if e != nil {
		return e
	}

	return nil
}

func (nl *DACSNetLink) SendMsgToKernel(msg []byte) error {
	desaddr := syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pad:    0,
		Pid:    0,
		Groups: 0,
	}

	dmsg := DACSNlMsgInit(msg)

	buf, n := dmsg.Serialize()
	if n > 0 {
		e := syscall.Sendto(nl.nlFd, buf, 0, &desaddr)
		if e != nil {
			return e
		}
	}

	return nil
}

type DACSNetlinkCfg struct {
	NetlinkProto int
	KernelStamp  string
}

type DACSNetlinkClient struct {
	netlinkProto int
	kernelStamp  string
	nl           *DACSNetLink
}

func NewDACSNetlinkClient(cfg *DACSNetlinkCfg) (*DACSNetlinkClient, error) {
	na := &DACSNetlinkClient{
		netlinkProto: cfg.NetlinkProto,
		kernelStamp:  cfg.KernelStamp,
	}

	na.nl = DACSNetLinkInit(na.netlinkProto)
	e := na.nl.BindPID()
	if e != nil {
		return nil, e
	}

	return na, e
}

//============================ Message Send To Kernel =========================

const (
	KMSG_ADD_SANDBOX          = 1
	KMSG_REMOVE_SANDBOX       = 2
	KMSG_SET_MASTER_PROC_INFO = 3
)

const (
	SANDBOX_INFO_DATA_SIZE        = 4270
	REMOVE_SANDBOX_INFO_MSG_SIZE  = 129
	SET_MASTER_PROC_INFO_MSG_SIZE = 4
	SANDBOX_ID_SIZE               = 128
)

/*
 *
 *
 *      No.1 -- receive net server pid (Type 1U)
 *              --------------------------------
 *              |    Type    |  Secrite Stamp  |
 *              --------------------------------
 *              |   4 bytes  |    16 bytes     |
 *              --------------------------------
 *
 *
 */
const (
	REGIST_SECRITE_STAMP_LEN = 16
)

func (na *DACSNetlinkClient) AddSandbox(sandboxId string, pid uint32, appWorkDir string) error {
	if len(sandboxId) != SANDBOX_ID_SIZE {
		return errors.New("invalid sandbox_id length")
	}

	if pid == 0 {
		return errors.New("invalid pid value")
	}

	appWorkDirLen := len(appWorkDir)
	if appWorkDirLen > 4096 || appWorkDirLen == 0 {
		return errors.New("invalid app work dir length")
	}

	msgType := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgType, KMSG_ADD_SANDBOX)

	msg := make([]byte, len(msgType)+SANDBOX_INFO_DATA_SIZE)
	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, pid)

	copy(msg[:len(msgType)], msgType[:])                      // copt msg type
	copy(msg[len(msgType):], sandboxId[:128])                 // copy sandbox id
	copy(msg[(len(msgType)+SANDBOX_ID_SIZE+1):], pidBytes[:]) // copy pid
	copy(msg[(len(msgType)+SANDBOX_ID_SIZE+1+4):], appWorkDir[:])

	return na.nl.SendMsgToKernel(msg)
}

func (na *DACSNetlinkClient) RemoveSandbox(sandboxId string) error {
	if len(sandboxId) != 128 {
		return errors.New("invalid sandbox_id length")
	}

	msgType := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgType, KMSG_REMOVE_SANDBOX)

	msg := make([]byte, len(msgType)+REMOVE_SANDBOX_INFO_MSG_SIZE)

	copy(msg[:len(msgType)], msgType[:])      // copt msg type
	copy(msg[len(msgType):], sandboxId[:128]) // copy sandbox id

	return na.nl.SendMsgToKernel(msg)
}

func (na *DACSNetlinkClient) SetMasterProInfo(masterPid uint32) error {
	if masterPid == 0 {
		errors.New("invalid pid")
	}

	msgType := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgType, KMSG_SET_MASTER_PROC_INFO)
	msg := make([]byte, len(msgType)+SET_MASTER_PROC_INFO_MSG_SIZE)

	copy(msg[:len(msgType)], msgType[:]) // copt msg type
	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, masterPid)
	copy(msg[len(msgType):], pidBytes[:]) // copy pid
	fmt.Printf("len = %d, MSG : %v\n", len(msg), msg)

	return na.nl.SendMsgToKernel(msg)
}