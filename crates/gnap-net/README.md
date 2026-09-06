# GNAP network address policy

`public_ip` is the conservative public-unicast predicate shared by the
conformance workbench and the delegation demo's push-finish transport. It uses
only the Rust standard library. The policy and its regression cases were moved
unchanged from the workbench; this extraction does not broaden allowed ranges.

The predicate deliberately rejects some legitimate special-purpose public
addresses, as well as private, local, documentation, multicast and IPv6
transition ranges. It is an application safety policy, not a GNAP requirement
or a complete implementation of the IANA address registries.

Address classification alone does not prevent SSRF. Callers must constrain the
destination, check every resolved address, pin the checked addresses when
connecting, prevent redirects and enforce time and size bounds. Any local
development exception belongs to that caller, not to `public_ip`.
