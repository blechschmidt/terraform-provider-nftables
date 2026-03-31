package testutils

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// CreateTestNamespace creates an isolated network namespace for testing
// and returns the namespace name. The namespace is automatically cleaned
// up when the test completes.
func CreateTestNamespace(t *testing.T) string {
	t.Helper()

	name := fmt.Sprintf("tfnft_test_%d_%d", time.Now().UnixNano(), rand.Intn(10000))

	cmd := exec.Command("ip", "netns", "add", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create test namespace %s: %v\n%s", name, err, out)
	}

	t.Cleanup(func() {
		cmd := exec.Command("ip", "netns", "delete", name)
		_ = cmd.Run()
	})

	return name
}

// RunInNamespace runs a command inside the given network namespace.
func RunInNamespace(t *testing.T, ns string, command string, args ...string) string {
	t.Helper()

	fullArgs := append([]string{"netns", "exec", ns}, append([]string{command}, args...)...)
	cmd := exec.Command("ip", fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Command failed in namespace %s: %s %v: %v\n%s", ns, command, args, err, out)
	}

	return strings.TrimSpace(string(out))
}

// RunNftInNamespace runs an nft command in the given namespace.
func RunNftInNamespace(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return RunInNamespace(t, ns, "nft", args...)
}

// AssertNftContains verifies that the nft output in a namespace contains
// the expected string.
func AssertNftContains(t *testing.T, ns string, nftArgs []string, expected string) {
	t.Helper()

	output := RunNftInNamespace(t, ns, nftArgs...)
	if !strings.Contains(output, expected) {
		t.Errorf("Expected nft output to contain %q, got:\n%s", expected, output)
	}
}

// AssertNftNotContains verifies that the nft output does NOT contain
// the specified string.
func AssertNftNotContains(t *testing.T, ns string, nftArgs []string, unexpected string) {
	t.Helper()

	output := RunNftInNamespace(t, ns, nftArgs...)
	if strings.Contains(output, unexpected) {
		t.Errorf("Expected nft output to NOT contain %q, got:\n%s", unexpected, output)
	}
}

// CheckNft returns a TestCheckFunc that verifies nft output contains expected string.
func CheckNft(t *testing.T, ns string, nftArgs []string, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fullArgs := append([]string{"netns", "exec", ns, "nft"}, nftArgs...)
		cmd := exec.Command("ip", fullArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft command failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), expected) {
			return fmt.Errorf("expected nft output to contain %q, got:\n%s", expected, string(out))
		}
		return nil
	}
}

// ProviderConfig returns an HCL provider configuration for a test namespace.
func ProviderConfig(namespace string) string {
	return fmt.Sprintf(`
provider "nftables" {
  namespace = %q
}
`, namespace)
}
