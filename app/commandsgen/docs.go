package commandsgen

import (
	"bytes"
	"fmt"
	"strings"
)

type DocsFile struct {
	FileName string
}

func GenerateDocsFiles(commands Commands) (map[string][]byte, error) {
	w := &docWriter{
		fileMap: make(map[string]*bytes.Buffer),
	}

	// sort by parent command (activity, batch, etc)
	for _, cmd := range commands.CommandList {
		if err := cmd.writeDoc(w); err != nil {
			return nil, fmt.Errorf("failed writing docs for command %s: %w", cmd.FullName, err)
		}
	}

	// Format and return
	var finalMap = make(map[string][]byte)
	for key, buf := range w.fileMap {
		finalMap[key] = buf.Bytes()
	}
	return finalMap, nil
}

type docWriter struct {
	fileMap map[string]*bytes.Buffer
}

func (c *Command) writeDoc(w *docWriter) error {
	// If this is a root command, write a new file
	if c.Depth == 1 {
		w.writeCommand(c)
	}
	return nil
}

func (w *docWriter) writeCommand(c *Command) {
	fileName := c.FileName
	w.fileMap[fileName] = &bytes.Buffer{}
	w.fileMap[fileName].WriteString("---\n")
	w.fileMap[fileName].WriteString("id: " + fileName + "\n")
	w.fileMap[fileName].WriteString("title: " + c.FullName + " command reference\n")
	w.fileMap[fileName].WriteString("sidebar_label: " + c.LeafName + "\n")
	w.fileMap[fileName].WriteString("description: " + c.Summary + "\n")
	w.fileMap[fileName].WriteString("slug: /cloud/tcld/" + c.LeafName + "\n")
	w.fileMap[fileName].WriteString("toc_max_heading_level: 5\n")
	w.fileMap[fileName].WriteString("keywords:\n")
	w.fileMap[fileName].WriteString("  - " + "cli reference" + "\n")
	w.fileMap[fileName].WriteString("  - " + "tcld" + "\n")
	w.fileMap[fileName].WriteString("tags:\n")
	w.fileMap[fileName].WriteString("  - " + "cli-reference" + "\n")
	w.fileMap[fileName].WriteString("  - " + "tcld" + "\n")
	w.fileMap[fileName].WriteString("---\n\n")

	w.writeCommandVisitor(c)
}

func (w *docWriter) writeCommandVisitor(c *Command) {
	if c.Depth > 1 {
		prefix := strings.Repeat("#", c.Depth)
		w.fileMap[c.FileName].WriteString(fmt.Sprintf("%s %s\n\n", prefix, c.LeafName))
	}
	w.fileMap[c.FileName].WriteString(c.Description + "\n\n")
	if len(c.Short) > 0 {
		w.fileMap[c.FileName].WriteString("Alias: `" + c.Short + "`\n\n")
	}

	if len(c.Children) == 0 {
		w.writeCommandOptions(c)
	}

	w.writeSubcommandToc(c)

	for _, c := range c.Children {
		w.writeCommandVisitor(c)
	}
}

func (w *docWriter) writeSubcommandToc(c *Command) {
	for _, c := range c.Children {
		w.fileMap[c.FileName].WriteString(fmt.Sprintf("- [%s](#%s)\n", c.FullName, c.LeafName))
	}
	if len(c.Children) > 0 {
		w.fileMap[c.FileName].WriteString("\n")
	}
}

func (w *docWriter) writeCommandOptions(c *Command) {
	if c.MaxChildDepth > 0 {
		return
	}
	prefix := strings.Repeat("#", c.Depth+1)

	for _, option := range c.Options {
		w.fileMap[c.FileName].WriteString(fmt.Sprintf("%s --%s\n\n", prefix, option.Name))
		w.fileMap[c.FileName].WriteString(option.Description + "\n\n")
		if len(option.Short) > 0 {
			w.fileMap[c.FileName].WriteString("Alias: `" + option.Short + "`\n\n")
		}
	}
}
