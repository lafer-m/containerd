package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/containerd"
	criapi "github.com/containerd/containerd/api/services/dacscri/v1"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/cryptsetup"
	"github.com/containerd/containerd/pkg/dacscri/utils"
	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (c *service) Remove(ctx context.Context, req *criapi.RemoveContainerRequest) (*types.Empty, error) {
	if req.ID == "" {
		return nil, ErrInvalidParam
	}

	client := c.client
	timeout := 10 * time.Second

	ctx = namespaces.WithNamespace(ctx, "default")
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	walker := &utils.ContainerWalker{
		Client: client,
		OnFound: func(ctx context.Context, found utils.FoundC) error {
			if err := stopContainer(ctx, found.Container, timeout); err != nil {
				if errdefs.IsNotFound(err) {
					log.G(ctx).Errorf("Error response from daemon: No such container: %s\n", found.Req)
					return nil
				}
				return err
			}

			log.G(ctx).Info("%s\n", found.Req)
			return nil
		},
	}

	n, err := walker.Walk(ctx, req.ID)
	if err != nil {
		log.G(ctx).Errorf("walk containers err: %v", err)
		return nil, ErrFindContainer
	} else if n == 0 {
		log.G(ctx).Infof("no such container %s", req.ID)
		return nil, ErrNoSuchContainer
	}

	// delete container
	dataStore, err := utils.GetDataStore()
	if err != nil {
		return nil, err
	}

	walker1 := &utils.ContainerWalker{
		Client: client,
		OnFound: func(ctx context.Context, found utils.FoundC) error {
			stateDir := filepath.Join(dataStore, "containers", "default", found.Container.ID())
			err = removeContainer(ctx, client, "default", found.Container.ID(), found.Req, true, dataStore, stateDir)
			return err
		},
	}

	n, err = walker1.Walk(ctx, req.ID)
	if err != nil {
		log.G(ctx).Errorf("walk containers err: %v", err)
		return nil, ErrFindContainer
	} else if n == 0 {
		log.G(ctx).Infof("no such container %s", req)
	}
	return &types.Empty{}, nil
}

func stopContainer(ctx context.Context, container containerd.Container, timeout time.Duration) error {
	task, err := container.Task(ctx, cio.Load)
	if err != nil {
		return err
	}

	status, err := task.Status(ctx)
	if err != nil {
		return err
	}

	paused := false

	switch status.Status {
	case containerd.Created, containerd.Stopped:
		return nil
	case containerd.Paused, containerd.Pausing:
		paused = true
	default:
	}

	// NOTE: ctx is main context so that it's ok to use for task.Wait().
	exitCh, err := task.Wait(ctx)
	if err != nil {
		return err
	}

	if timeout > 0 {
		signal, err := containerd.ParseSignal("SIGTERM")
		if err != nil {
			return err
		}

		if err := task.Kill(ctx, signal); err != nil {
			return err
		}

		// signal will be sent once resume is finished
		if paused {
			if err := task.Resume(ctx); err != nil {
				log.G(ctx).Warnf("Cannot unpause container %s: %s", container.ID(), err)
			} else {
				// no need to do it again when send sigkill signal
				paused = false
			}
		}

		sigtermCtx, sigtermCtxCancel := context.WithTimeout(ctx, timeout)
		defer sigtermCtxCancel()

		err = waitContainerStop(sigtermCtx, exitCh, container.ID())
		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	signal, err := containerd.ParseSignal("SIGKILL")
	if err != nil {
		return err
	}

	if err := task.Kill(ctx, signal); err != nil {
		return err
	}

	// signal will be sent once resume is finished
	if paused {
		if err := task.Resume(ctx); err != nil {
			logrus.Warnf("Cannot unpause container %s: %s", container.ID(), err)
		}
	}
	return waitContainerStop(ctx, exitCh, container.ID())
}

func waitContainerStop(ctx context.Context, exitCh <-chan containerd.ExitStatus, id string) error {
	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "wait container %v", id)
	case status := <-exitCh:
		return status.Error()
	}
}

func removeContainer(ctx context.Context, client *containerd.Client, ns, id, req string, force bool, dataStore, stateDir string) (retErr error) {
	// var name string
	defer func() {
		if errdefs.IsNotFound(retErr) {
			retErr = nil
		}
		if retErr == nil {
			retErr = os.RemoveAll(stateDir)
		} else {
			logrus.WithError(retErr).Warnf("failed to remove container %q", id)
		}
	}()
	container, retErr := client.LoadContainer(ctx, id)
	if retErr != nil {
		return retErr
	}

	task, retErr := container.Task(ctx, cio.Load)
	if retErr != nil {
		if errdefs.IsNotFound(retErr) {
			if container.Delete(ctx, containerd.WithSnapshotCleanup) != nil {
				return container.Delete(ctx)
			}
		}
		return retErr
	}

	_, retErr = task.Delete(ctx)
	if retErr != nil && !errdefs.IsNotFound(retErr) {
		return errors.Wrapf(retErr, "failed to delete task %v", id)
	}

	var delOpts []containerd.DeleteOpts
	if _, err := container.Image(ctx); err == nil {
		delOpts = append(delOpts, containerd.WithSnapshotCleanup)
	}

	if err := container.Delete(ctx, delOpts...); err != nil {
		return err
	}
	// delete encrypt files
	encrypt, err := cryptsetup.LoadCryptState(filepath.Join(stateDir, CryptState))
	if err != nil {
		return err
	}
	encrptPath := filepath.Join(dataStore, encrptDir, namespaces.Default, id)
	img := fmt.Sprintf("%s.img", encrptPath)
	dev := &cryptsetup.CryptDevice{}
	retErr = dev.CloseSecureFS(encrypt, encrptPath)
	if retErr == nil {
		retErr = os.Remove(img)
		retErr = os.RemoveAll(encrptPath)
	}
	return nil
}
