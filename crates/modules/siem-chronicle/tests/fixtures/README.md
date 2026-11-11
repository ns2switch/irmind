# Synthetic OAuth signing fixture

This fixture is for connector contract tests. The RSA private key and matching
public key are generated test material. They are not service credentials and
are never used outside the local synthetic HTTP server. Tests verify the JWT
signature, fixed audience, scope and bounded lifetime.
