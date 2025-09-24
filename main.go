package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

var (
	configFile = flag.String("c", "/etc/ndppd.conf", "Path to configuration file")
	daemonize  = flag.Bool("d", false, "Daemonize")
	pidFile    = flag.String("p", "", "Path to PID file")
	verbose    = flag.Bool("v", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	if !*verbose {
		log.SetOutput(io.Discard)
	}

	if *daemonize {
		args := os.Args[1:]
		for i, arg := range args {
			if arg == "-d" {
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Start()
		fmt.Println("Daemon started with PID:", cmd.Process.Pid)
		os.Exit(0)
	}

	fmt.Printf("Config file: %s\n", *configFile)
	fmt.Printf("PID file: %s\n", *pidFile)
	fmt.Printf("Verbose: %t\n", *verbose)

	// Load configuration
	config, err := ParseConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration: %+v\n", config)

	if *pidFile != "" {
		f, err := os.Create(*pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating PID file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		fmt.Fprintf(f, "%d\n", os.Getpid())
	}

	// Start the proxy
	startProxy(config)
}

func startProxy(config *Config) {
	for _, proxy := range config.Proxies {
		go startProxyInstance(proxy)
	}

	// Wait forever
	select {}
}
