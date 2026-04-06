## Summary

Describe what changed and why.

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Refactor
- [ ] CI / release

## Core-only checklist

- [ ] This change does not add Pro-only runtime code to the Core repository.
- [ ] No MaxMind/GeoLite2 or local GeoIP database dependency was introduced.
- [ ] Public API behaviour remains compatible with existing Core deployments.
- [ ] Any deployment/config changes are documented.

## Validation

- [ ] `python -m compileall -q app main.py main_panel.py`
- [ ] Docker Compose config checked, if deployment files changed.
- [ ] Manual smoke test completed, if API/panel behaviour changed.

## Notes for reviewers

Add screenshots, logs, migration notes, or rollout risks if relevant.
