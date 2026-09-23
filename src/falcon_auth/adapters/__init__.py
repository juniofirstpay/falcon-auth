"""The Falcon integration — the only place in this package that imports Falcon.

Everything else is driven by plain values, so the cores stay exercisable without a web framework
and a non-Falcon consumer could use them unchanged.

⚠ Named `adapters` rather than `falcon` deliberately: a subpackage called `falcon` inside a
package that imports `falcon` resolves correctly under Python 3's absolute imports but reads
ambiguously and confuses tooling.

⚠ **Every hook absorbs stray keyword arguments.** `falcon.before(action, *args, **kwargs)`
forwards all of them to the hook, including the `is_async=True` that callers across this
ecosystem still pass believing Falcon consumes it. Falcon 3 did; Falcon 4 detects hooks
automatically and the parameter is gone, so it now arrives as a stray kwarg — and a strict
`(req, resp, resource, params)` signature raises `TypeError`, which is a **500 on a gated
route**. Nothing is read from them, on purpose: a gate that changed behaviour based on decorator
kwargs would be a second, invisible configuration surface.

Planned modules:
    middleware.py       the plane → [methods] authentication middleware (C-038)
    authenticators.py   RemoteJWKSAuthenticator
    hooks.py            require · require_elevated · require_service_scope · require_callback
    errors.py           register_error_handlers
"""
