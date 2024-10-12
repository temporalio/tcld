// Package commandsgen is built to read the YAML format described in
// temporalcli/commandsgen/commands.yml and generate code from it.
package commandsgen

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

func EnrichCommands(m Commands) (Commands, error) {
	commandLookup := make(map[string]*Command)

	for i, command := range m.CommandList {
		if err := m.CommandList[i].processSection(); err != nil {
			return Commands{}, fmt.Errorf("failed parsing command section %q: %w", command.FullName, err)
		}

		m.CommandList[i].Index = i
		commandLookup[command.FullName] = &m.CommandList[i]
	}

	var rootCommand *Command

	//populate parent and basic meta
	for i, c := range m.CommandList {
		commandLength := len(strings.Split(c.FullName, " "))
		if commandLength == 1 {
			rootCommand = &m.CommandList[i]
			continue
		}
		parentName := strings.Join(strings.Split(c.FullName, " ")[:commandLength-1], " ")
		parent, ok := commandLookup[parentName]
		if ok {
			m.CommandList[i].Parent = &m.CommandList[parent.Index]
			m.CommandList[i].Depth = len(strings.Split(c.FullName, " ")) - 1
			m.CommandList[i].FileName = strings.Split(c.FullName, " ")[1]
			m.CommandList[i].LeafName = strings.Join(strings.Split(c.FullName, " ")[m.CommandList[i].Depth:], "")
		}
	}

	//populate children and base command
	for _, c := range m.CommandList {
		if c.Parent == nil {
			continue
		}

		//fmt.Printf("add child: %s\n", m.CommandList[c.Index].FullName)
		m.CommandList[c.Parent.Index].Children = append(m.CommandList[c.Parent.Index].Children, &m.CommandList[c.Index])

		base := &c
		for base.Depth > 1 {
			base = base.Parent
		}
		m.CommandList[c.Index].Base = &m.CommandList[base.Index]
	}

	setMaxChildDepthVisitor(*rootCommand, &m)

	for i, c := range m.CommandList {
		if c.Parent == nil {
			continue
		}

		subCommandStartDepth := 1
		if c.Base.MaxChildDepth > 2 {
			subCommandStartDepth = 2
		}

		subCommandName := ""
		if c.Depth >= subCommandStartDepth {
			subCommandName = strings.Join(strings.Split(c.FullName, " ")[subCommandStartDepth:], " ")
		}

		if len(subCommandName) == 0 && c.Depth == 1 {
			//for operator base command to show up in tags, keywords, etc.
			subCommandName = c.LeafName
		}

		m.CommandList[i].SubCommandName = subCommandName
	}

	// sort children by max child depth (desc) and then full name (desc)
	// which is how we want tcld docs pages sorted
	sortChildrenVisitor(rootCommand)

	// pull flat list in same order as sorted children
	m.CommandList = make([]Command, 0)
	collectCommandVisitor(*rootCommand, &m)

	/*
		for _, command := range m.CommandList {
			fmt.Printf("sort result: %s\n", command.FullName)
		}
	*/

	return m, nil
}

func collectCommandVisitor(c Command, m *Commands) {

	m.CommandList = append(m.CommandList, c)

	for _, child := range c.Children {
		collectCommandVisitor(*child, m)
	}
}

func sortChildrenVisitor(c *Command) {
	sort.Slice(c.Children, func(i, j int) bool {
		if c.Children[i].MaxChildDepth != c.Children[j].MaxChildDepth {
			return c.Children[i].MaxChildDepth < c.Children[j].MaxChildDepth
		}

		return c.Children[i].FullName < c.Children[j].FullName
	})
	for _, command := range c.Children {
		sortChildrenVisitor(command)
	}

}

func setMaxChildDepthVisitor(c Command, commands *Commands) int {
	maxChildDepth := 0
	children := commands.CommandList[c.Index].Children
	if len(children) > 0 {
		for _, child := range children {
			depth := setMaxChildDepthVisitor(*child, commands)
			if depth > maxChildDepth {
				maxChildDepth = depth
			}
		}
	}

	commands.CommandList[c.Index].MaxChildDepth = maxChildDepth
	return maxChildDepth + 1
}
