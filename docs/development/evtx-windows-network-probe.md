# Windows EVTX network probe proposal

This proposal is for maintainers validating the experimental decoder's network boundary. It changes the measurement of isolation, not the permissions granted to the decoder. It is not implemented.

## Property to verify

No decoder traffic may reach the host, a private network or the internet. Retain the zero-capability AppContainer, explicit three-handle inheritance list, read-only evidence, private runtime ACLs, child-process restriction and kill-on-close Job Object. There is no unconfined fallback.

Windows network isolation filters traffic through WFP. It does not provide the same socket-creation contract as a Linux seccomp filter. A bound socket is not evidence that external traffic can pass, and a loopback block can produce a timeout rather than an immediate permission error. Same-process loopback is a distinct case and is not communication outside the container.

References: [Microsoft network-isolation documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall), [AppContainer capabilities](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), and [a Microsoft repository reproduction of same-container versus host loopback](https://github.com/microsoft/mxc/issues/1261).

## Proposed bounded witness

1. Before launch, the broker checks that BFE and MpsSvc are running. It creates IPv4 and IPv6 loopback listeners and verifies them with broker-to-broker positive controls. This uses no external address or provider.
2. A fixed, private runtime challenge contains only the selected local ports and a fresh nonce. The broker owns it; the container receives read access. It contains no evidence or credentials. Evidence still arrives only through the inherited read-only handle. No new inherited handle, executable argument or ambient credential is introduced.
3. Before parsing evidence, the decoder checks its token, capabilities, file restrictions and runtime handles. It then attempts connections to both live broker listeners. A successful connection fails containment. A timeout alone never proves containment: the broker must also observe that its live listeners received no connection.
4. For inbound tests, a bounded containment frame announces decoder-owned loopback listeners. The decoder retains them while the broker attempts to connect. The decoder checks for accepted connections while waiting for a nonce-bound acknowledgement in a broker-written, read-only runtime file. This prevents early listener closure from being mistaken for isolation. Neither direction sends case data.
5. The broker acknowledges only a verified result. Refusal, missing/malformed frames, dead endpoints, unavailable IPv6, unexpected errors, failed service checks, expired deadlines or an accepted connection make EVTX unavailable. No generic timeout or connection error is silently accepted.
6. Capabilities remain empty. The documented WFP capability policy covers private/internet destinations; local witnesses test host isolation without probing remote addresses. The evidence distinguishes this policy assumption from an empirical test of every network destination.

The challenge, acknowledgement and containment frames are bounded internal runtime messages, outside signed custody formats. Validate lengths, ports, nonce and frame order. Keep their files within the existing private child runtime, grant only the exact container SID read access, reject links and remove them on success, failure and cancellation. Parent publication still requires authenticated source bytes, a complete protocol trailer, a verified network witness and successful child exit.

## Required tests

- Positive controls detect intentionally reachable test listeners.
- Both IPv4 and IPv6 reject traffic between the decoder and the host in both directions.
- A timeout with a dead endpoint, wrong nonce, missing acknowledgement or early listener closure fails closed.
- Stopped/unavailable WFP services make the module unavailable; tests do not enable services or alter firewall rules silently.
- Native tests retain foreign-file denial, runtime-write denial, explicit handle exclusion, process termination, cancellation and startup cleanup.
- The witness cannot read ground truth, evidence or credentials and cannot publish a partial ingestion.

If socket creation itself must be prohibited on Windows, this AppContainer proposal does not claim that guarantee. Keep Windows EVTX unavailable until a different reviewed mechanism meets it. Linux and macOS denial probes remain unchanged.
