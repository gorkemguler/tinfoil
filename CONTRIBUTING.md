# Contributing

The most useful contribution is **a new check**, and the second most useful is
**killing a false positive**.

## Adding a check

Every check lives in `tinfoil.py`, is one function, and follows the same shape:

```python
@check("check-id", "Human readable title", "system",
       severity=HIGH, weight=7, platforms=("Darwin", "Linux"))
def chk_something():
    rc, out, _ = run(["some", "command"])
    if bad_thing_in(out):
        return Result(FAIL, "one line saying what an attacker gets",
                      details=["specifics, one per line"],
                      fix=["the exact command to fix it"])
    return Result(PASS, "one line saying what is fine")
```

Rules the existing checks follow:

1. **Never escalate.** No `sudo`, no prompting. If a check needs privileges it
   returns `Result(SKIP, "<why>")`. A skipped check is excluded from the score
   rather than counted as a pass.
2. **Never mutate.** Print the fix command; do not run it.
3. **Never call the network.** CI fails the build if a networking import appears.
4. **Redact.** Any discovered secret goes through `redact()` before it reaches
   `details`.
5. **Never raise.** `run()` and `read_text()` already swallow errors and return
   empty values; assume every command may be missing and every file unreadable.
6. **Say what an attacker gets.** "`~/.aws/credentials` is 0644 - group and others
   can read AWS long-lived access keys" beats "insecure permissions".
7. **Do not suggest a fix that breaks things.** `path-hygiene` deliberately does
   *not* tell you to `chmod g-w /opt/homebrew/bin`, because that breaks Homebrew.
   If the safe answer is "know about this", say that instead.

Pick `weight` relative to the existing table in the README: 12 is "the disk is
readable by a thief", 3 is "mildly stale".

## Prototyping outside the repo

Drop the same function in `~/.tinfoil/checks/anything.py` and it loads on the next
run, with all the helpers already in scope. Once it earns its place, move it into
`tinfoil.py` and open a PR.

## Before you open a PR

```bash
python3 -m unittest test_tinfoil     # must pass
python3 tinfoil.py --all             # your check should appear, correctly
python3 tinfoil.py --json | python3 -m json.tool > /dev/null
```

If your change alters what the report prints, re-record the README recordings so the
documentation does not drift:

```bash
brew install vhs     # once
make gif             # rewrites assets/demo.gif and assets/ci.gif
```

The tapes are sized to hold the report without wrapping or scrolling. Adding lines to
the demo output can push the score off the top of the frame, so read the comment at the
top of `assets/demo.tape` before re-recording.

Add a test for any parsing or classification logic — the pure functions
(`scan_secrets`, `_key_is_encrypted`, `_is_public`, `score_of`) all have tests to
copy from. Checks that shell out are covered by
`test_every_check_returns_a_result_on_this_machine`, which runs every check and
asserts it produces a sane result on the CI runner.

## Reporting a false positive

Open an issue with the check id, the `--json` entry for it, and what the correct
answer would have been. A false positive is a bug: it trains people to ignore the
report.

## Reporting a security issue

If you find a way to make `tinfoil` leak an unredacted secret, write to something
other than a public issue tracker first.
