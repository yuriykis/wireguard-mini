//go:build mage

package main

import (
	"os"
	"os/exec"
)

// Test runs all Go tests.
func Test() error {
	cmd := exec.Command("go", "test", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
