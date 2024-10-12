package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/temporalio/tcld/app/commandsgen"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Get commands dir
	_, file, _, _ := runtime.Caller(0)
	docsDir := filepath.Join(file, "../../../../docs/")

	err := os.MkdirAll(docsDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating directory: %v", err)
	}

	cmds, err := commandsgen.ConvertCommands()
	if err != nil {
		return fmt.Errorf("failed converting commands: %w", err)
	}

	//Write the `temporal` CLI style YAML for easier reference
	yamlData, err := yaml.Marshal(&cmds)

	if err != nil {
		fmt.Printf("Error while Marshaling. %v", err)
	}

	filePath := filepath.Join(file, "../../../../commandsgen/tcld.yml")
	err = os.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write command yaml into %s", filePath)
	}

	// Enrich commands
	cmds, err = commandsgen.EnrichCommands(cmds)
	if err != nil {
		return fmt.Errorf("failed enriching commands: %w", err)
	}

	// Generate docs
	b, err := commandsgen.GenerateDocsFiles(cmds)
	if err != nil {
		return err
	}

	// Write
	for filename, content := range b {
		filePath := filepath.Join(docsDir, filename+".mdx")
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			return fmt.Errorf("failed writing file: %w", err)
		}
	}

	return nil
}
