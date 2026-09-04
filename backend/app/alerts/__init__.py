"""Alerts: latches LoonInspect holds open while something is true of the fleet.

The contract is docs/alerts.md. `app.alerts.service` owns the closed kind vocabulary,
the pure delta the latch is decided by, and the two database halves (open/close at
sync, purge at retention). Nothing here reaches the wire — the `alert` block's shape is
named in docs/alerts.md and emitted by nobody (#101, ruled 2026-09-04).
"""
