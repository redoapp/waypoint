package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/redoapp/waypoint/internal/covreport"
)

func main() {
	output := flag.String("o", "coverage/report.html", "output HTML file path")
	serve := flag.String("serve", "", "start an HTTP server on this address (e.g. :8080) to view the report")
	open := flag.Bool("open", false, "open the report in a browser (requires -serve)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: covreport [-o report.html] [-serve :8080] [-open] name=path [name=path ...]\n")
		fmt.Fprintf(os.Stderr, "\nGenerates a color-coded HTML coverage report from multiple coverage profiles.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	profiles := make(map[string]string)
	for _, arg := range flag.Args() {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid argument %q: expected name=path\n", arg)
			os.Exit(1)
		}
		profiles[parts[0]] = parts[1]
	}

	if *serve != "" {
		var buf bytes.Buffer
		if err := covreport.Generate(&buf, profiles); err != nil {
			fmt.Fprintf(os.Stderr, "generating report: %v\n", err)
			os.Exit(1)
		}
		html := buf.Bytes()

		ln, err := net.Listen("tcp", *serve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen %s: %v\n", *serve, err)
			os.Exit(1)
		}

		url := fmt.Sprintf("http://localhost:%d", ln.Addr().(*net.TCPAddr).Port)
		fmt.Printf("Serving coverage report at %s\n", url)

		if *open {
			openBrowser(url)
		}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(html)
		})
		if err := http.Serve(ln, nil); err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			os.Exit(1)
		}
		return
	}

	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := covreport.Generate(f, profiles); err != nil {
		fmt.Fprintf(os.Stderr, "generating report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Coverage report written to %s\n", *output)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
