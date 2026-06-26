package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/temporalio/tcld/app"
	"github.com/urfave/cli/v2"
)

func main() {
	outputDir := flag.String("output", ".", "Output directory for generated docs")
	flag.Parse()

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("failed creating output directory: %v", err)
	}

	commands := buildCommandTree()

	for _, cmd := range commands {
		filename := filepath.Join(*outputDir, cmd.Name+".mdx")
		content := generateCommandPage(cmd)
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			log.Fatalf("failed writing %s: %v", filename, err)
		}
		fmt.Printf("wrote %s\n", filename)
	}

	indexContent := generateIndexPage(commands)
	indexPath := filepath.Join(*outputDir, "index.mdx")
	if err := os.WriteFile(indexPath, []byte(indexContent), 0644); err != nil {
		log.Fatalf("failed writing index: %v", err)
	}
	fmt.Printf("wrote %s\n", indexPath)
}

func buildCommandTree() []*cli.Command {
	// The New*Command constructors store client functions in Before hooks
	// but don't call them during construction, so nil functions are safe here.
	nilFn := func(fn interface{}) interface{} { return fn }
	_ = nilFn

	var commands []*cli.Command

	constructors := []func() (app.CommandOut, error){
		func() (app.CommandOut, error) { return app.NewAccountCommand(nil) },
		func() (app.CommandOut, error) { return app.NewAPIKeyCommand(nil) },
		func() (app.CommandOut, error) { return app.NewCertificatesCommand() },
		func() (app.CommandOut, error) { return app.NewConnectivityRuleCommand(nil) },
		func() (app.CommandOut, error) { return app.NewFeatureCommand() },
		func() (app.CommandOut, error) { return app.NewLoginCommand() },
		func() (app.CommandOut, error) { return app.NewLogoutCommand() },
		func() (app.CommandOut, error) { return app.NewMigrationCommand(nil) },
		func() (app.CommandOut, error) { return app.NewNamespaceCommand(nil) },
		func() (app.CommandOut, error) { return app.NewNexusCommand(nil) },
		func() (app.CommandOut, error) { return app.NewRequestCommand(nil) },
		func() (app.CommandOut, error) { return app.NewServiceAccountCommand(nil) },
		func() (app.CommandOut, error) { return app.NewUserCommand(nil) },
		func() (app.CommandOut, error) { return app.NewUserGroupCommand(nil) },
		func() (app.CommandOut, error) { return app.NewVersionCommand() },
	}

	for _, ctor := range constructors {
		out, err := ctor()
		if err != nil {
			log.Printf("warning: failed to construct command: %v", err)
			continue
		}
		if out.Command != nil {
			commands = append(commands, out.Command)
		}
	}

	sort.Slice(commands, func(i, j int) bool {
		return commands[i].Name < commands[j].Name
	})

	return commands
}

func generateCommandPage(cmd *cli.Command) string {
	var b strings.Builder

	description := cmd.Usage
	if description == "" {
		description = fmt.Sprintf("Reference for tcld %s commands", cmd.Name)
	}

	// Frontmatter
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %s\n", cmd.Name))
	b.WriteString(fmt.Sprintf("title: tcld %s command reference\n", cmd.Name))
	b.WriteString(fmt.Sprintf("sidebar_label: %s\n", cmd.Name))
	b.WriteString(fmt.Sprintf("description: %s\n", description))
	b.WriteString(fmt.Sprintf("slug: /cloud/tcld/%s\n", cmd.Name))
	b.WriteString("toc_max_heading_level: 4\n")
	b.WriteString("keywords:\n")
	b.WriteString("  - cli reference\n")
	b.WriteString("  - tcld\n")
	b.WriteString("tags:\n")
	b.WriteString("  - Temporal Cloud\n")
	b.WriteString("  - tcld\n")
	b.WriteString("---\n\n")

	// Auto-generated comment
	b.WriteString("{/* This is an auto-generated file. Do not edit directly. */}\n\n")

	writeCommand(&b, cmd, "tcld", 2)

	return b.String()
}

func writeCommand(b *strings.Builder, cmd *cli.Command, parentPath string, headingLevel int) {
	fullPath := parentPath + " " + cmd.Name
	heading := strings.Repeat("#", headingLevel)
	usage := cmd.Usage
	if usage != "" && usage[len(usage)-1] == '.' {
		usage = usage[:len(usage)-1]
	}

	escapedUsage := escapeMDX(usage)

	if usage == "" {
		if headingLevel > 2 {
			b.WriteString(fmt.Sprintf("%s %s\n\n", heading, cmd.Name))
		}
	} else if headingLevel == 2 {
		b.WriteString(fmt.Sprintf("The `%s` command %s.\n\n", fullPath, lowercaseFirst(escapedUsage)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n\n", heading, cmd.Name))
		b.WriteString(fmt.Sprintf("The `%s` command %s.\n\n", fullPath, lowercaseFirst(escapedUsage)))
	}

	if len(cmd.Aliases) > 0 {
		b.WriteString(fmt.Sprintf("Alias: `%s`\n\n", strings.Join(cmd.Aliases, "`, `")))
	}

	if len(cmd.Subcommands) > 0 {
		// List subcommands
		for _, sub := range cmd.Subcommands {
			if sub.Hidden {
				continue
			}
			b.WriteString(fmt.Sprintf("- [tcld %s %s](#%s)\n", fullPath[5:], sub.Name, sub.Name))
		}
		b.WriteString("\n")

		// Recurse into subcommands
		for _, sub := range cmd.Subcommands {
			if sub.Hidden {
				continue
			}
			writeCommand(b, sub, fullPath, headingLevel+1)
		}
	}

	// Write flags
	visibleFlags := getVisibleFlags(cmd.Flags)
	if len(visibleFlags) > 0 {
		flagHeading := strings.Repeat("#", headingLevel+1)
		for _, f := range visibleFlags {
			names := f.Names()
			if len(names) == 0 {
				continue
			}
			primaryName := names[0]

			b.WriteString(fmt.Sprintf("%s --%s\n\n", flagHeading, primaryName))

			usage := getFlagUsage(f)
			if usage != "" {
				b.WriteString(fmt.Sprintf("%s\n\n", escapeMDX(usage)))
			}

			aliases := getFlagAliases(f)
			if len(aliases) > 0 {
				b.WriteString(fmt.Sprintf("Alias: `%s`\n\n", strings.Join(aliases, "`, `")))
			}
		}
	}
}

func getVisibleFlags(flags []cli.Flag) []cli.Flag {
	var visible []cli.Flag
	for _, f := range flags {
		if isHidden(f) {
			continue
		}
		visible = append(visible, f)
	}
	return visible
}

func isHidden(f cli.Flag) bool {
	switch ff := f.(type) {
	case *cli.StringFlag:
		return ff.Hidden
	case *cli.BoolFlag:
		return ff.Hidden
	case *cli.IntFlag:
		return ff.Hidden
	case *cli.Int64Flag:
		return ff.Hidden
	case *cli.Float64Flag:
		return ff.Hidden
	case *cli.PathFlag:
		return ff.Hidden
	case *cli.StringSliceFlag:
		return ff.Hidden
	default:
		return false
	}
}

func getFlagUsage(f cli.Flag) string {
	switch ff := f.(type) {
	case *cli.StringFlag:
		return ff.Usage
	case *cli.BoolFlag:
		return ff.Usage
	case *cli.IntFlag:
		return ff.Usage
	case *cli.Int64Flag:
		return ff.Usage
	case *cli.Float64Flag:
		return ff.Usage
	case *cli.PathFlag:
		return ff.Usage
	case *cli.StringSliceFlag:
		return ff.Usage
	default:
		return ""
	}
}

func getFlagAliases(f cli.Flag) []string {
	names := f.Names()
	if len(names) <= 1 {
		return nil
	}
	return names[1:]
}

func generateIndexPage(commands []*cli.Command) string {
	var b strings.Builder

	b.WriteString(`---
id: index
title: tcld command reference
sidebar_label: CLI (tcld)
description: The Temporal Cloud CLI (tcld) is a command-line tool for interacting with Temporal Cloud, offering commands for account management, login, namespace, and more. Install via Homebrew or build from source.
slug: /cloud/tcld
toc_max_heading_level: 4
keywords:
  - operation-guide
  - tcld
tags:
  - Temporal Cloud
  - tcld
---

{/* This is an auto-generated file. Do not edit directly. */}

The Temporal Cloud CLI (tcld) is a command-line tool that you can use to interact with Temporal Cloud.

- [How to install tcld](#install-tcld)

### tcld commands

`)

	for _, cmd := range commands {
		b.WriteString(fmt.Sprintf("- [tcld %s](/cloud/tcld/%s)\n", cmd.Name, cmd.Name))
	}

	b.WriteString(`
### Global modifiers

#### --auto_confirm

Automatically confirm all prompts.

You can specify the value for this modifier by setting the AUTO_CONFIRM environment variable.
The default value is ` + "`false`" + `.

## How to install tcld {/* #install-tcld */}

You can install [tcld](/cloud/tcld) in two ways.

### Install tcld by using Homebrew

` + "```bash\nbrew install temporalio/brew/tcld\n```" + `

### Build tcld from source

1. Verify that you have Go 1.18 or later installed.

   ` + "```bash\n   go version\n   ```" + `

   If Go 1.18 or later is not installed, follow the [Download and install](https://go.dev/doc/install) instructions on the Go website.

1. Clone the tcld repository and run make.

   ` + "```bash\n   git clone https://github.com/temporalio/tcld.git\n   cd tcld\n   make\n   ```" + `

1. Copy the tcld executable to any directory that appears in the PATH environment variable, such as ` + "`/usr/local/bin`" + `.

   ` + "```bash\n   cp tcld /usr/local/bin/tcld\n   ```" + `

1. Verify that tcld is installed.

   ` + "```bash\n   tcld version\n   ```" + `
`)

	return b.String()
}

func escapeMDX(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "{", "&#123;")
	s = strings.ReplaceAll(s, "}", "&#125;")
	return s
}

func lowercaseFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
