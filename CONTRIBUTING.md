# Contributing

Thanks for helping! The project deliberately has **no runtime or test dependencies**, so it builds offline with just a JDK 17+.

## Build and test

```sh
sh build.sh   # compile, run unit tests, package dist/hostbaseline.jar
sh demo.sh    # run the examples and verify the documented exit codes
```

On Windows use `.\build.ps1` and `.\demo.ps1`.

## Adding a check

1. Add a rule in `Audit.rules` with a stable ID, a matcher (`Rule.oneOf(...)` or `Rule.Range`), severity, rationale, review-style remediation and a reference link. Never reuse or renumber an existing ID.
2. Add the key to `examples/hardened` (passing) and to `examples/risky` (failing) as appropriate, and to `examples/router` if relevant.
3. Add passing, failing and unknown cases to `Tests.java`.
4. Regenerate the table: `java -jar dist/hostbaseline.jar --list-checks` and update `docs/CHECKS.md`; update the example counts in the README.
5. Add a line to `CHANGELOG.md`.

## Principles

- Read-only: never execute commands, contact hosts or modify settings.
- `UNKNOWN` is not `PASS`: missing, conflicting or uninterpretable evidence must never pass.
- Do not claim compliance with a standard; reference documentation instead.
