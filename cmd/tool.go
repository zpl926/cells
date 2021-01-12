package cmd

import "github.com/spf13/cobra"

// ToolCmd are tools that do not need a running Cells instance
var ToolCmd = &cobra.Command{
	Use:   "tool",
	Short: "Various tools",
	Long: `Tooling commands that do not require a running Cells instance.
`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	RootCmd.AddCommand(ToolCmd)
}
