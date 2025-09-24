package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Rule represents a rule in the configuration file.
type Rule struct {
	Address string
	Iface   string
	Auto    bool
	Static  bool
}

// Proxy represents a proxy in the configuration file.
type Proxy struct {
	Interface     string
	TTL           int
	Timeout       int
	Router        bool
	RewriteSource bool
	Rules         []Rule
}

// Config represents the entire configuration.
type Config struct {
	Proxies []Proxy
}

// ParseConfig parses the configuration file at the given path.
func ParseConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	scanner := bufio.NewScanner(file)
	var currentProxy *Proxy
	var currentRule *Rule
	inProxy := false
	inRule := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		switch {
		case parts[0] == "proxy" && len(parts) >= 2:
			proxy := Proxy{
				Interface: parts[1],
				Router:    true,
				TTL:       30000,
				Timeout:   500,
			}
			config.Proxies = append(config.Proxies, proxy)
			currentProxy = &config.Proxies[len(config.Proxies)-1]
			inProxy = true
		case parts[0] == "rule" && len(parts) >= 2 && inProxy:
			rule := Rule{Address: parts[1]}
			currentProxy.Rules = append(currentProxy.Rules, rule)
			currentRule = &currentProxy.Rules[len(currentProxy.Rules)-1]
			inRule = true
		case parts[0] == "{" && (inProxy || inRule):
			// Start of a block
		case parts[0] == "}" && inRule:
			inRule = false
			currentRule = nil
		case parts[0] == "}" && inProxy:
			inProxy = false
			currentProxy = nil
		case inRule && len(parts) == 1:
			switch parts[0] {
			case "auto":
				currentRule.Auto = true
			case "static":
				currentRule.Static = true
			}
		case inRule && len(parts) >= 2:
			switch parts[0] {
			case "iface":
				currentRule.Iface = parts[1]
			}
		case inProxy && len(parts) >= 2:
			switch parts[0] {
			case "ttl":
				val := 0
				fmt.Sscanf(parts[1], "%d", &val)
				currentProxy.TTL = val
			case "timeout":
				val := 0
				fmt.Sscanf(parts[1], "%d", &val)
				currentProxy.Timeout = val
			case "router":
				currentProxy.Router = (parts[1] == "yes")
			case "rewrite_source":
				currentProxy.RewriteSource = (parts[1] == "yes")
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}
