package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Short: "a server that computes sha256",
}

func main() {
	rootCmd.Execute()
}
