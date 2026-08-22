"""The tenant app catalog: every distinct (name, bundle ID, version) the fleet has shown,
when it was first and last seen on any device, and what Jamf's patch catalog says about it —
pre-filled from Jamf's titles by hash, decided by the title requirements, kept current by a
background refresh after every catalog sync. See docs/app-catalog.md."""
