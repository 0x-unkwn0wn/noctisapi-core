NoctisAPI Core Automations

This document describes automatic behavior in the Core edition.

Sessions (event grouping)
- Events are grouped into sessions based on actor identity and time proximity.
- The exact logic is implemented in `app/honeypot_public.py`.

No campaign recompute is included in Core.
