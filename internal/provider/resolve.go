package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// resolveNamespacePath turns a namespace specification into an nsfs path that
// can be opened and handed to nftables.WithNetNSFd.
//
// Supported forms:
//
//	"<name>"            -> /var/run/netns/<name> (ip netns add)
//	"name:<name>"       -> the same, stated explicitly
//	"pid:<pid>"         -> /proc/<pid>/ns/net
//	"path:<path>"       -> the path verbatim
//	"docker:<id|name>"  -> the network namespace of a running Docker container,
//	                       resolved through the Docker API (its init PID)
//
// The "docker:" form lets a Terraform module target a container created by the
// docker provider without a shell helper, e.g.
// namespace = "docker:${docker_container.gateway.id}".
func resolveNamespacePath(spec string) (string, error) {
	kind, val, hasPrefix := strings.Cut(spec, ":")
	if !hasPrefix {
		return "/var/run/netns/" + spec, nil
	}
	switch kind {
	case "name":
		return "/var/run/netns/" + val, nil
	case "path":
		return val, nil
	case "pid":
		return "/proc/" + val + "/ns/net", nil
	case "docker":
		pid, err := dockerInitPID(val)
		if err != nil {
			return "", fmt.Errorf("resolving docker namespace %q: %w", spec, err)
		}
		return fmt.Sprintf("/proc/%d/ns/net", pid), nil
	default:
		return "", fmt.Errorf("unknown namespace kind %q (want name:, pid:, path: or docker:)", kind)
	}
}

// dockerInitPID returns the init PID of a running container, queried over the
// Docker Engine API on the local socket. Honours DOCKER_HOST when it names a
// unix socket; otherwise defaults to /var/run/docker.sock.
func dockerInitPID(idOrName string) (int, error) {
	socket := "/var/run/docker.sock"
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		socket = strings.TrimPrefix(h, "unix://")
	}

	httpc := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}

	resp, err := httpc.Get("http://docker/containers/" + idOrName + "/json")
	if err != nil {
		return 0, fmt.Errorf("querying docker socket %s: %w", socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("docker inspect of %q returned HTTP %d", idOrName, resp.StatusCode)
	}

	var info struct {
		State struct {
			Pid     int  `json:"Pid"`
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return 0, fmt.Errorf("decoding docker inspect of %q: %w", idOrName, err)
	}
	if !info.State.Running || info.State.Pid == 0 {
		return 0, fmt.Errorf("container %q is not running (pid %d)", idOrName, info.State.Pid)
	}
	return info.State.Pid, nil
}
