package main

import (
	"os"
	"testing"

	"github.com/shoenig/test/must"
)

func TestWriteSecureFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		directory   string
		fileName    string
		content     string
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "ValidWrite",
			directory:   tempDir,
			fileName:    "test.txt",
			content:     "Test content",
			wantErr:     false,
			expectedErr: "",
		},
		{
			name:        "ValidAbsolutePath",
			directory:   "/tmp",
			fileName:    "hello.txt",
			content:     "Hi there",
			wantErr:     false,
			expectedErr: "",
		},
		{
			name:        "InvalidFileSystemBoundaries",
			directory:   "/etc",
			fileName:    "hosts",
			content:     "Test content",
			wantErr:     true,
			expectedErr: "permission denied",
		},
		{
			name:        "InvalidDirectory",
			directory:   "./nonexistent-directory",
			fileName:    "test.txt",
			content:     "Test content",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "InvalidFileName",
			directory:   tempDir,
			fileName:    "",
			content:     "Test content",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "PathTraversalInFileName",
			directory:   "./safe-directory",
			fileName:    "../../../../../etc/passwd",
			content:     "Test content",
			wantErr:     true,
			expectedErr: "path escapes from parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := writeSecureFile(tt.directory, tt.fileName, tt.content)
			if tt.wantErr {
				must.Error(t, err)
				must.StrContains(t, err.Error(), tt.expectedErr)
			} else {
				must.NoError(t, err)
				must.FileExists(t, tt.directory+"/"+tt.fileName)
			}
			if !tt.wantErr {
				os.RemoveAll(tt.directory)
			}
		})
	}
}

func TestReadSecureFile(t *testing.T) {
	tests := []struct {
		name        string
		directory   string
		fileName    string
		content     string
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "ValidRead",
			directory:   "./safe-directory",
			fileName:    "example.txt",
			content:     "Test content",
			wantErr:     false,
			expectedErr: "",
		},
		{
			name:        "AbsolutePath",
			directory:   "/tmp",
			fileName:    "hello.txt",
			content:     "Hi there",
			wantErr:     false,
			expectedErr: "",
		},
		{
			name:        "FileNotFound",
			directory:   "./safe-directory",
			fileName:    "nonexistent.txt",
			content:     "",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "InvalidDirectory",
			directory:   "./nonexistent-directory",
			fileName:    "test.txt",
			content:     "",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "PathTraversal",
			directory:   "./safe-directory",
			fileName:    "../example.txt",
			content:     "Test content",
			wantErr:     true,
			expectedErr: "path escapes from parent",
		},
		{
			name:        "Symlink",
			directory:   "./safe-directory",
			fileName:    "symlink_to_passwd",
			content:     "",
			wantErr:     true,
			expectedErr: "path escapes from parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSecureFile(tt.directory, tt.fileName)
			if tt.wantErr {
				must.Error(t, err)
				must.StrContains(t, err.Error(), tt.expectedErr)
			} else {
				must.NoError(t, err)
				must.NotNil(t, got)
			}
		})
	}
}

func TestWriteAtomicSwap(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		directory   string
		fileName    string
		content     string
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "AtomicSwap",
			directory:   tempDir,
			fileName:    "atomic.txt",
			content:     "Atomic content",
			wantErr:     false,
			expectedErr: "",
		},
		{
			name:        "InvalidDirectory",
			directory:   "./nonexistent-directory",
			fileName:    "atomic.txt",
			content:     "Atomic content",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "InvalidFileName",
			directory:   tempDir,
			fileName:    "",
			content:     "Atomic content",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
		{
			name:        "Symlink",
			directory:   tempDir,
			fileName:    "symlink_to_passwd",
			content:     "Atomic content",
			wantErr:     true,
			expectedErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := os.OpenRoot(tt.directory)
			if err != nil {
				if tt.wantErr {
					must.Error(t, err)
					must.StrContains(t, err.Error(), tt.expectedErr)
					return
				}
				t.Fatalf("failed to open root: %v", err)
			}
			defer root.Close()

			tmpFile, err := root.Create("temp-" + tt.fileName)
			if err != nil {
				if tt.wantErr {
					must.Error(t, err)
					must.StrContains(t, err.Error(), tt.expectedErr)
					return
				}
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer tmpFile.Close()

			_, err = tmpFile.WriteString(tt.content)
			if err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}

			err = tmpFile.Close()
			if err != nil {
				t.Fatalf("failed to close temp file: %v", err)
			}

			err = os.Rename(tmpFile.Name(), tt.directory+"/"+tt.fileName)
			if tt.wantErr {
				must.Error(t, err)
				must.StrContains(t, err.Error(), tt.expectedErr)
			} else {
				must.NoError(t, err)
				must.FileExists(t, tt.directory+"/"+tt.fileName)
			}

			if !tt.wantErr {
				os.RemoveAll(tt.directory)
			}
		})
	}
}
