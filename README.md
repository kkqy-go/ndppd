# ndppd - Neighbor Discovery Protocol Proxy Daemon

`ndppd` is a lightweight and efficient daemon for proxying IPv6 Neighbor Discovery Protocol (NDP) packets on Linux. It listens for Neighbor Solicitation (NS) messages on a given interface and can either provide a static reply or forward the request to another interface based on a flexible ruleset.

This project is a Go implementation of the original C++ `ndppd` found at [https://github.com/DanielAdolfsson/ndppd](https://github.com/DanielAdolfsson/ndppd).

This is particularly useful in complex network environments, such as those with Proxmox or other virtualization platforms, where you need to bridge NDP messages between a host and its virtual machines or containers.

## Features

-   **Rule-Based Proxying:** Forward or reply to NDP requests based on a simple configuration file.
-   **Static Replies:** Respond to NS requests for specific prefixes with the host's own MAC address.
-   **Interface Forwarding:** Forward NS requests that match a rule to a different network interface.
-   **Automatic Forwarding:** (Linux-only) Automatically find the correct interface to forward to by reading the system's IPv6 route table.
-   **Daemonization:** Runs as a background process.
-   **High Performance:** Built in Go with raw sockets for high-speed packet handling.

## Configuration

`ndppd` is controlled by a configuration file, typically located at `/etc/ndppd.conf`. The file consists of one or more `proxy` blocks, each defining a listening interface and a set of rules.

### Example `ndppd.conf`

```
# Proxy NDP packets on the eth0 interface
proxy eth0 {
    # Set the router flag on Neighbor Advertisements.Default is yes.
    router yes

    # When enabled, outgoing Neighbor Solicitations (NS) from a link-local source address will have their source address rewritten to the global address prefix from the matching rule. It is useful in some PVE environments.Default is no.
    rewrite_source no


    # Rule for a static prefix. ndppd will reply to any NS request
    # for an address within this prefix using its own MAC address.
    rule 2001:db8:1::/48 {
        static
    }

    # Rule for forwarding. ndppd will forward any NS request
    # for an address within this prefix to the eth1 interface.
    rule 2001:db8:2::/48 {
        iface eth1
    }

    # Rule for automatic forwarding. ndppd will look up the correct
    # interface in the kernel route table and forward the packet.
    rule 2001:db8:3::/48 {
        auto
    }
}
```

### Proxy Options

-   `router [yes|no]`: (Default: `yes`) Whether to set the "is-router" flag in Neighbor Advertisement replies.
-   `ttl <milliseconds>`: (Default: `30000`) Not currently implemented.
-   `timeout <milliseconds>`: (Default: `500`) Not currently implemented.
-   `rewrite_source [yes|no]`: (Default: `no`) When enabled, outgoing Neighbor Solicitations (NS) from a link-local source address will have their source address rewritten to the global address prefix from the matching rule.

### Rule Types

Each `rule` block defines a prefix and an action.

-   `static`: Responds to NS requests with a Neighbor Advertisement (NA) from the host interface.
-   `iface <interface>`: Forwards the NS packet to the specified `<interface>`.
-   `auto`: Looks up the destination IP in `/proc/net/ipv6_route` and forwards the packet to the appropriate interface.

## Building

This is a standard Go project. Ensure you have a recent version of Go installed.

```sh
go build
```

This will produce a binary named `ndppd` in the current directory.

## Usage

`ndppd` requires root privileges to create raw sockets.

```sh
# Run in the foreground with a local config file
sudo ./ndppd -c ndppd.conf

# Run as a daemon using the default config path
sudo ./ndppd -d
```

### Command-Line Flags

-   `-c <path>`: Path to the configuration file (default: `/etc/ndppd.conf`).
-   `-d`: Run as a daemon (background process).
-   `-p <path>`: Path to write a PID file (e.g., `/var/run/ndppd.pid`).
-   `-v`: Verbose logging level (not currently implemented).

## Dependencies

-   [github.com/google/gopacket](https://github.com/google/gopacket): For packet decoding and encoding.

## Platform

This tool is designed specifically for **Linux** due to its reliance on `AF_PACKET` raw sockets and the `/proc/net/ipv6_route` file for the `auto` rule functionality. It will not run on other operating systems like Windows or macOS.
