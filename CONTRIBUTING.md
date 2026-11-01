# Contributing to aioice

Thank you for your interest in improving aioice! This document describes
how changes are expected to be made, whether they are written by hand or
with the help of a tool.

Please report security vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md), not through issues or pull requests. Everyone
taking part in the project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

aioice is written in pure Python. Install it in editable mode, together
with the tools used by continuous integration:

```
pip install -e . -r requirements/lint.txt -r requirements/test.txt
```

Setting the `AIOICE_DEBUG` environment variable enables debug logging
while running the tests.

Work on a branch and open a pull request against `main`.

## Correctness

**Specifications are the authority.** When fixing a bug or implementing
new code, ground the implementation in the relevant specification and read
the actual text rather than relying on memory. aioice follows the IETF
RFCs, for instance:

- ICE: RFC 8445 (which obsoletes RFC 5245), 8838 (trickle ICE), 6544 (TCP
  candidates), 7675 (consent freshness)
- STUN: RFC 5389, 8489
- TURN: RFC 5766, 8656
- mDNS candidates: draft-ietf-mmusic-mdns-ice-candidates

Note where a MUST, SHOULD or MAY applies, and justify behaviour changes
in comments and commit messages.

**Make the smallest change that closes the gap.** Keep a fix to its stated
aim and reuse existing helpers rather than porting a specification's
pseudocode wholesale. List any further alignment with the specification as
separate follow-ups.

**Browsers are the interoperability reference.** aioice provides the ICE
layer of [aiortc](https://github.com/aiortc/aiortc), which is tested against
Chrome and Firefox. libwebrtc, Firefox and common STUN / TURN servers such
as coturn are useful to understand what peers actually do, and a link to the
relevant change or bug is welcome when a behaviour exists for
interoperability. They are not a source of truth where they deviate from the
specifications.

**Review your changes critically.** Look for side effects on other code
paths, and treat remote peers and STUN / TURN servers as untrusted: consider
how a malicious party could abuse the new behaviour, in particular when
parsing STUN messages or candidates.

## Scope

aioice implements ICE, STUN, TURN and mDNS candidates. Issues with the
layers above ICE, such as SDP, DTLS, SRTP, SCTP or media, belong in
[aiortc](https://github.com/aiortc/aiortc).

GitHub issues are not the place for usage questions, especially questions
about `asyncio` rather than aioice. A good question can often be written as
a suggestion to improve the documentation.

## Code style

Readability is one of aioice's key goals. Prefer plain, idiomatic Python
over compact or clever code. When a performance or memory argument exists,
measure it and present the trade-off rather than assuming it wins.

Avoid duplicating code. Before adding a helper, look for an existing one
that can be reused or extended, and factor out logic that would otherwise
be copied.

Use f-strings in new code. Logger calls are the exception: they keep lazy
`%` arguments, using the class's `__log_debug` or `__log_info` helper where
one exists.

In the library code, insert new functions and methods in alphabetical
order rather than appending them. Do not reorder existing code unless
that is the purpose of the change.

## Comments

Write comments as sentences: start with a capital letter and end with a
full stop. Do not reformat existing comments unless that is the purpose of
the change.

Keep comments short, typically one or two lines. State the non-obvious
reason and cite the specification section in parentheses (e.g. "(RFC 8445
section 7.2.5.3)"); longer quotes belong in the commit message.

## Tests

Code contributions must come with full unit test coverage. ICE is a
complex protocol, and ensuring correct behaviour now and in the future
requires a proper investment in automated testing.

Tests exchange packets over local sockets, and can use the following
helpers:

- `@asynctest` from `tests/utils.py` to run a coroutine test method;
- `invite_accept()` from `tests/utils.py` to exchange candidates and
  credentials between two `Connection` instances;
- `read_message()` from `tests/utils.py` to read a captured STUN message
  from a `tests/data/*.bin` file, for parser tests;
- `async with run_turn_server()` from `tests/turnserver.py` to run a local
  STUN / TURN server over UDP, TCP and TLS;
- `async with run_echo_server()` from `tests/echoserver.py` to run a local
  UDP echo server, for instance as a TURN peer.

Continuous integration lacks IPv6, so tests that need it are skipped there
using `RUNNING_ON_CI` from `tests/test_ice.py`.

## Checks

Before submitting, run the checks that continuous integration runs, from
the repository root:

```
coverage run -m unittest discover -v
coverage report -m
ruff check
ruff format --check
mypy
check-manifest
```

## Commit messages

Keep commit messages concise. The subject line states what the commit does
in the imperative; the body explains *why*: the goal being pursued, the
constraint that forced the approach, the non-obvious insight behind the
change. Skip anything a reader can trivially deduce from the diff: do not
enumerate the modified files, restate renamed symbols, or narrate the
changes function by function.

Quote a specification only where its wording matters, such as the MUST or
SHOULD that justifies a behaviour change, and keep the quote to the
relevant sentence. When the fix is obvious from the specification, citing
the section is enough.

Reference GitHub issues in a trailer at the end of the message, not inline
in the body. Use `Fixes: #N` only when the commit fully resolves the
issue, otherwise `See: #N`.

The changelog (`docs/changelog.rst`) is written at release time, so do not
update it in your pull request.
