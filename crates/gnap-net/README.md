# gnap-net

Decide whether an IP address is a public unicast address before your application connects to it. `public_ip` is a conservative predicate, without dependencies beyond the Rust standard library, shared by the diagnostic workbench and the delegation lab.

Add it with `cargo add gnap-net`. Its [API documentation](https://docs.rs/gnap-net) is on docs.rs.

The predicate deliberately rejects some legitimate special-purpose public addresses, as well as private, local, documentation, multicast and IPv6 transition ranges. It's a safety policy for applications, not a GNAP requirement or a full implementation of the IANA registries.

Address classification alone doesn't prevent SSRF. Callers must constrain the destination, check every resolved address, pin the checked addresses, refuse redirects and bound time and size. A local development exception belongs to the caller, not to `public_ip`.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
