//go:build mage

package main

import (
	"os"
	"os/exec"
)

// Build compiles the wireguard-mini binary.
func Build() error {
	if err := os.MkdirAll("bin", 0o755); err != nil {
		return err
	}

	cmd := exec.Command("go", "build", "-o", "bin/wireguard-mini", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Test runs all Go tests.
func Test() error {
	cmd := exec.Command("go", "test", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Lint runs golangci-lint on all packages.
func Lint() error {
	cmd := exec.Command("golangci-lint", "run", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
