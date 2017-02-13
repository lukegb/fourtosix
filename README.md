# fourtosix

*a v4-to-v6 proxy*

**fourtosix** is a proxy which tunnels v4 connections (including, primarily, TLS) through to v6 hosts. This is useful if you're deploying v6-only machines, and wish to still allow connectivity over IPv4.

At present, it only supports TLS-with-SNI (for HTTPS). On a connection, it will inspect the information sent by the client to determine the backend to connect to, which can be limited by a whitelist of suffixes (to avoid becoming an open proxy!).

If you're deploying it in the recommended 4-in-6 configuration, you will need the following:

* A prefix (at least a /96) delegated to the machine on which this software is running
* Have run `ip -6 route add local [prefix] dev lo`
* Ensure the `net.ipv6.ip_nonlocal_bind` sysctl is set to `1`

then you can run this software with the `-v4-subnet [prefix]` flag set. Outbound connections will then appear to come from this subnet, with the original IPv4 address being the suffix.

NB: If Go supported `IP_TRANSPARENT` then the sysctl wouldn't be required - the sysctl is perfectly adequate for my usecase, however, and is significantly less work than reimplementing the internals of the `net` package.
