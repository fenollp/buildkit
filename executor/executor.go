package executor

import (
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"syscall"

	"github.com/containerd/containerd/v2/core/mount"
	resourcestypes "github.com/moby/buildkit/executor/resources/types"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/network"
	"github.com/moby/sys/user"
)

type Meta struct {
	Args           []string
	Env            []string
	User           string
	Cwd            string
	OldCwd         string
	Hostname       string
	Tty            bool
	ReadonlyRootFS bool
	ExtraHosts     []HostIP
	Ulimit         []*pb.Ulimit
	CDIDevices     []*pb.CDIDevice
	CgroupParent   string
	LinuxResources *pb.LinuxResources
	NetMode        pb.NetMode
	SecurityMode   pb.SecurityMode
	ValidExitCodes []int
	Proxy          *network.ProxyConfig

	RemoveMountStubsRecursive bool
}

// ProcessEnv returns the environment to start the process with, including the
// OLDPWD a POSIX shell would have recorded had it entered Cwd with cd(1). A
// shell reads PWD off the working directory of its own process, but nothing
// tells it which directory that process came from, so OLDPWD has to be handed
// over explicitly. A value the build set itself takes precedence, so that it
// can override or opt out of this one.
func (m Meta) ProcessEnv() []string {
	if m.OldCwd == "" {
		return m.Env
	}
	for _, env := range m.Env {
		if name, _, _ := strings.Cut(env, "="); name == "OLDPWD" {
			return m.Env
		}
	}
	return append(slices.Clone(m.Env), "OLDPWD="+m.OldCwd)
}

type MountableRef interface {
	Mount() ([]mount.Mount, func() error, error)
	IdentityMapping() *user.IdentityMapping
}

type Mountable interface {
	Mount(ctx context.Context, readonly bool) (MountableRef, error)
}

type Mount struct {
	Src      Mountable
	Selector string
	Dest     string
	Readonly bool
}

type WinSize struct {
	Rows uint32
	Cols uint32
}

type ProcessInfo struct {
	Meta           Meta
	Stdin          io.ReadCloser
	Stdout, Stderr io.WriteCloser
	Resize         <-chan WinSize
	Signal         <-chan syscall.Signal
}

type Executor interface {
	// Run will start a container for the given process with rootfs, mounts.
	// `id` is an optional name for the container so it can be referenced later via Exec.
	// `started` is an optional channel that will be closed when the container setup completes and has started running.
	Run(ctx context.Context, id string, rootfs Mount, mounts []Mount, process ProcessInfo, started chan<- struct{}) (resourcestypes.Recorder, error)
	// Exec will start a process in container matching `id`. An error will be returned
	// if the container failed to start (via Run) or has exited before Exec is called.
	Exec(ctx context.Context, id string, process ProcessInfo) error
}

type HostIP struct {
	Host string
	IP   net.IP
}
