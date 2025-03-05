package main

import (
	"fmt"
	"io"
	"os"
)

// Create the symlink
// ln -s ../../../../../etc/passwd ./safe-directory/symlink_to_passwd

func writeSecureFile(directory, fileName, content string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()

	file, err := root.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func readSecureFile(directory, fileName string) (string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()

	file, err := root.Open(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func main() {
	directory := "./safe-directory"
	fileName := "example.txt"
	content := "Secure content\n"

	if err := writeSecureFile(directory, fileName, content); err != nil {
		fmt.Println("Error writing file:", err)
		return
	}

	fmt.Printf("File written securely inside %s/%s\n", directory, fileName)

	readContent, err := readSecureFile(directory, fileName)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Println("Read from file:", readContent)
}
