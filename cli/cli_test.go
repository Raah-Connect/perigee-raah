package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePathReturnsAbsolutePath(t *testing.T) {
	dir := t.TempDir()

	got, err := validatePath(dir)
	if err != nil {
		t.Fatalf("validatePath(%q) error: %v", dir, err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("validatePath(%q) = %q, want absolute path", dir, got)
	}
	abs, _ := filepath.Abs(dir)
	if got != abs {
		t.Errorf("validatePath(%q) = %q, want %q", dir, got, abs)
	}
}

func TestValidatePathRejectsMissingAndFiles(t *testing.T) {
	if _, err := validatePath(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected error for missing path")
	}

	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePath(f); err == nil {
		t.Error("expected error for non-directory path")
	}
}

func TestWriteToFileUsesOutputDir(t *testing.T) {
	dir := t.TempDir()
	if err := writeToFile([]byte("data"), dir, "~sampel-palnet", 1, "", ".key"); err != nil {
		t.Fatalf("writeToFile error: %v", err)
	}
	want := filepath.Join(dir, "sampel-palnet-1.key")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected file at %s: %v", want, err)
	}
}
