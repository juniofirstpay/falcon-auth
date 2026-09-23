"""Part 1 — east-west: peer services over mTLS.

Authorizes a service-plane call by mapping the peer certificate's Common Name to an explicit
set of `noun:verb` scopes. ⛔ An unknown or unmapped CN gets **zero** scopes and is denied; an
empty allow-list rejects everything and never means "allow all".

The CN is read from `scope["extensions"]["tls"]["peer_cert_der"]`, which `mtls` injects. This
part **trusts** that CN: chain validation is TLS's job, delegated to the handshake, where
`CERT_OPTIONAL` means an unverifiable certificate never reaches the application.

⚠ `mtls` is the one module here that is **boot-time transport wiring** rather than a
request-time decision — it configures uvicorn's SSL context so a CN can be read at all.

Planned modules:
    verifier.py    Verifier · AllowList · build_allow_list · peer_cn
    mtls.py        build_uvicorn_ssl_kwargs · peer-cert protocols
    errors.py      MissingClientCertError · UnknownCNError · MissingScopeError
"""
