package utils

import (
	"context"
	"io"
	"net/url"
	"os"

	"github.com/containerd/console"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/pkg/errors"
)

// NewTask is from https://github.com/containerd/containerd/blob/v1.4.3/cmd/ctr/commands/tasks/tasks_unix.go#L70-L108
func NewTask(ctx context.Context, client *containerd.Client, container containerd.Container, flagI, flagT, flagD bool, con console.Console, logURI string) (containerd.Task, error) {
	stdinC := &StdinCloser{
		Stdin: os.Stdin,
	}
	var ioCreator cio.Creator
	if flagT {
		if con == nil {
			return nil, errors.New("got nil con with flagT=true")
		}
		ioCreator = cio.NewCreator(cio.WithStreams(con, con, nil), cio.WithTerminal)
	} else if flagD && logURI != "" {
		// TODO: support logURI for `nerdctl run -it`
		u, err := url.Parse(logURI)
		if err != nil {
			return nil, err
		}
		ioCreator = cio.LogURI(u)
	} else {
		var in io.Reader
		if flagI {
			in = stdinC
		}
		ioCreator = cio.NewCreator(cio.WithStreams(in, os.Stdout, os.Stderr))
	}
	t, err := container.NewTask(ctx, ioCreator)
	if err != nil {
		return nil, err
	}
	stdinC.Closer = func() {
		t.CloseIO(ctx, containerd.WithStdinCloser)
	}
	return t, nil
}

// StdinCloser is from https://github.com/containerd/containerd/blob/v1.4.3/cmd/ctr/commands/tasks/exec.go#L181-L194
type StdinCloser struct {
	Stdin  *os.File
	Closer func()
}

func (s *StdinCloser) Read(p []byte) (int, error) {
	n, err := s.Stdin.Read(p)
	if err == io.EOF {
		if s.Closer != nil {
			s.Closer()
		}
	}
	return n, err
}
