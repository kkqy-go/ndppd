# Gemini Project Context: ndppd

## Project Overview

This project is a **Neighbor Discovery Protocol Proxy Daemon (ndppd)** written in Go. Its primary function is to listen for IPv6 Neighbor Discovery Protocol (NDP) packets, specifically Neighbor Solicitations, on a network interface. Based on a user-defined ruleset, it can then generate and send Neighbor Advertisement replies or forward the requests to another interface.

This is useful in network scenarios where you need to proxy NDP messages between different network segments.

The core logic involves:
- Creating raw IPv6 sockets to capture and send packets on specific interfaces.
- Using the `gopacket` library to decode and encode ICMPv6 and Ethernet frames.
- A configuration file parser that defines which interfaces to monitor and what rules to apply.
- The ability to run as a background daemon process.

## Building and Running

### Building

This is a standard Go project. To build the binary, run:

```sh
go build
```

This will produce an executable file named `ndppd` (or `ndppd.exe` on Windows).

### Running

The daemon requires a configuration file to run. The path can be specified with the `-c` flag. It also requires elevated privileges to create raw sockets.

1.  **Create a configuration file.** A typical configuration might look like this (e.g., `ndppd.conf`):

    ```
    proxy eth0 {
        router yes
        ttl 30000
        timeout 500
        rule 2001:db8:1::/48 {
            static
        }
        rule 2001:db8:2::/48 {
            iface eth1
        }
    }
    ```

2.  **Run the daemon:**

    ```sh
    # Run in the foreground, pointing to a local config file
    sudo ./ndppd -c ndppd.conf

    # Run as a daemon in the background
    sudo ./ndppd -c /etc/ndppd.conf -d
    ```

### Command-Line Flags

-   `-c <path>`: Path to the configuration file (default: `/etc/ndppd.conf`).
-   `-d`: Daemonize and run in the background.
-   `-p <path>`: Path to write a PID file.
-   `-v`: Verbose level.

## Development Conventions

-   **Dependencies:** Project dependencies are managed using Go Modules (`go.mod` and `go.sum`). The primary external dependency is `github.com/google/gopacket`.
-   **Concurrency:** The application is concurrent, launching a separate goroutine for each `proxy` instance defined in the configuration.
-   **Platform:** The code appears to be designed for Linux, as it reads from `/proc/net/ipv6_route` to automatically find interfaces for some rule types.
-   **Configuration:** A custom parser in `config.go` handles the application's configuration format, which consists of nested `proxy` and `rule` blocks.
