package app

import (
	"bufio"
	"fmt"
	"os"
	"unicode"

	"github.com/urfave/cli/v2"
)

const (
	AutoConfirmFlagName = "auto-confirm"
)

var (
	AutoConfirmFlag = &cli.BoolFlag{
		Name:    AutoConfirmFlagName,
		Usage:   "Automatically confirm all prompts",
		EnvVars: []string{"AUTO_CONFIRM"},
	}
)

func ConfirmPrompt(ctx *cli.Context, msg string) (bool, error) {
	for {
		fmt.Printf("%s [y/n] ", msg)
		reader := bufio.NewReader(os.Stdin)
		var input rune
		if ctx.Bool(AutoConfirmFlagName) {
			fmt.Printf("y\n")
			input = rune('y')
		} else {
			var err error
			input, _, err = reader.ReadRune()
			if err != nil {
				return false, err
			}
		}
		switch unicode.ToLower(input) {
		case rune('y'):
			return true, nil
		case rune('n'):
			return false, nil
		default:
			fmt.Printf("invalid keypress, it does not match a boolean\n")
		}
	}
}
