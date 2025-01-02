// Package docsgen is built to convert the existing
// cli.Commands to a docs gen model and generate tcld docs from that
package docsgen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/temporalio/tcld/app"
	"github.com/urfave/cli/v2"
)

type converter struct {
	App         *cli.App
	CommandList []Command
}

func ConvertCommands() (Commands, error) {
	a, _ := app.NewApp(app.AppParams{})

	c := converter{
		App:         a,
		CommandList: make([]Command, 0),
	}

	err := c.addApp(asSlice(app.NewApp(app.AppParams{}))[0].(*cli.App))
	if err != nil {
		return Commands{}, err
	}

	err = c.addCommands(asSlice(app.NewNexusCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}

	err = c.addCommands(asSlice(app.NewVersionCommand())[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewAccountCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewNamespaceCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewUserCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewRequestCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewLoginCommand())[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewLogoutCommand())[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewCertificatesCommand())[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewAPIKeyCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewFeatureCommand())[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}
	err = c.addCommands(asSlice(app.NewServiceAccountCommand(nil))[0].(app.CommandOut))
	if err != nil {
		return Commands{}, err
	}

	commands := Commands{
		CommandList: c.CommandList,
	}

	return commands, nil
}

func (c *converter) addApp(a *cli.App) error {
	options := make([]Option, 0)
	for _, flag := range a.Flags {
		option, err := flagToOption(flag)
		if err != nil {
			return err
		}
		options = append(options, option)
	}

	c.CommandList = append(c.CommandList, Command{
		FullName:    a.Name,
		Summary:     formatSummary(a.Usage, a.Name),
		Description: formatCommandDescription(a.Description, ""),
		Options:     options,
	})

	return nil
}

func formatSummary(v string, site string) string {
	if len(v) == 0 {
		site = strings.ReplaceAll(site, " ", "-")
		v = "<missing-usage-for-site-" + site + " action=\"update in source .go file\">"
	}
	v = strings.TrimSuffix(v, ".")
	return v
}

func formatCommandDescription(v string, cmdName string) string {
	v = formatDescription(v, cmdName)

	if strings.Contains(v, "These commands") {
		v = strings.Replace(v, "These commands", fmt.Sprintf("The `%s` commands", cmdName), 1)
	} else {
		v = strings.Replace(v, "This command", fmt.Sprintf("The `%s` command", cmdName), 1)
	}

	return v
}

func formatDescription(v string, site string) string {
	if len(v) == 0 {
		site = strings.ReplaceAll(site, " ", "-")
		v = "<missing-description-for-site-" + site + " action=\"update in source .go file\">"
	}
	if !strings.HasSuffix(v, ".") {
		v = v + "."
	}

	return v
}

func (c *converter) addCommands(co app.CommandOut) error {
	return c.addCommandsVisitor(c.App.Name, co.Command)
}

func (c *converter) addCommandsVisitor(prefix string, cmd *cli.Command) error {
	name := fmt.Sprintf("%s %s", prefix, cmd.Name)

	options := make([]Option, 0)
	for _, flag := range cmd.Flags {
		option, err := flagToOption(flag)
		if err != nil {
			return err
		}
		options = append(options, option)
	}
	// alphabetize options
	sort.Slice(options, func(i, j int) bool {
		return options[i].Name < options[j].Name
	})

	c.CommandList = append(c.CommandList, Command{
		FullName:    name,
		Summary:     formatSummary(cmd.Usage, name),
		Description: formatCommandDescription(cmd.Description, name),
		Short:       getFirstAlias(cmd.Aliases),
		Options:     options,
	})

	for _, sc := range cmd.Subcommands {
		err := c.addCommandsVisitor(name, sc)
		if err != nil {
			return err
		}
	}

	return nil
}

func getFirstAlias(aliases []string) string {
	alias := ""
	if len(aliases) > 0 {
		alias = aliases[0]
	}
	return alias
}

func newOption(name string, usage string, required bool, aliases []string, optionType string) Option {
	return Option{
		Name:        name,
		Description: formatDescription(usage, name),
		Required:    required,
		Short:       getFirstAlias(aliases),
		Type:        optionType,
	}
}

func flagToOption(flag cli.Flag) (Option, error) {
	switch v := flag.(type) {
	case *cli.StringFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "string"), nil
	case *cli.StringSliceFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "string[]"), nil
	case *cli.IntFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "int"), nil
	case *cli.PathFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "string"), nil
	case *cli.BoolFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "bool"), nil
	case *cli.TimestampFlag:
		return newOption(v.Name, v.Usage, v.Required, v.Aliases, "timestamp"), nil
	default:
		return Option{}, fmt.Errorf("unknown flag type %#v", v)
	}
}

func asSlice(v ...interface{}) []interface{} {
	return v
}
