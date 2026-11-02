# Changelog

## 2.0.0
Major revision with breaking CLI, JSON and package changes. See `docs/RELEASE_NOTES.md` for the full list: 24 checks, numeric rules, strict UTF-8, named options, richer findings, router example and end-to-end CI verification.

Migration from 1.x: replace `<snapshot> <report> <role> <previous>` with `<snapshot> <report> --role <role> --baseline <previous>`; the JSON `expected` field is now a string and counts moved under `summary`.

## 1.0.1
Fixed the release workflow's tag handling.

## 1.0.0
Initial educational implementation: 12 checks, HTML and JSON reports, drift comparison, offline build scripts.
