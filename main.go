package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

var (
	configFile = flag.String("c", "/etc/ndppd.conf", "Path to configuration file")
	daemonize  = flag.Bool("d", false, "Daemonize")
	pidFile    = flag.String("p", "", "Path to PID file")
	verbose    = flag.Int("v", 0, "Enable verbose logging")
)

func main() {
	flag.Parse()

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
		logln(0, "Daemon started with PID:", cmd.Process.Pid)
		os.Exit(0)
	}

	logf(0, "Config file: %s\n", *configFile)
	logf(0, "PID file: %s\n", *pidFile)
	logf(0, "Verbose: %d\n", *verbose)

	// Load configuration
	config, err := ParseConfig(*configFile)
	if err != nil {
		errorf("Error parsing config file: %v\n", err)
		os.Exit(1)
	}

	logf(0, "Configuration: %+v\n", config)

	if *pidFile != "" {
		f, err := os.Create(*pidFile)
		if err != nil {
			panicf("Error creating PID file: %v\n", err)
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
