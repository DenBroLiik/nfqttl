# Tests

`cargo test` covers packet TTL/checksum behavior and input/config validation. Runtime netfilter tests require Android/root or a namespace fixture that provides NETLINK_NETFILTER and iptables; do not run them against a host firewall accidentally.
