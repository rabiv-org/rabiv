package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

type list []string

func (l *list) String() string     { return "repeatable" }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

func main() { os.Exit(mainExitCode()) }

func mainExitCode() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: rabiv-collector capture|process")
	}
	switch args[0] {
	case "capture":
		return runCapture(ctx, args[1:], out)
	case "process":
		return runProcess(ctx, args[1:], out)
	default:
		return errors.New("unknown Collector command")
	}
}

type outputOptions struct {
	channel string
	id      string
}

func commandFlags(name string) (*flag.FlagSet, *outputOptions) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	output := &outputOptions{}
	f.StringVar(&output.channel, "output-channel", "", "root-owned output channel config")
	f.StringVar(&output.id, "id", "", "immutable snapshot/manifest ID")
	return f, output
}
