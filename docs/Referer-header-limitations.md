# Referer header limitations

Obscura implements the default `strict-origin-when-cross-origin` behavior for
native document navigation, but not every request path currently receives the
source document URL needed to produce a `Referer` header.

This page describes the behavior in v0.2.2 and the current development branch.
It is a compatibility limitation, not a CAPTCHA or anti-bot workaround.

## Current behavior

| Request path | Current behavior |
| --- | --- |
| Direct automation navigation, including the first `Page.navigate` or `page.goto()` | No `Referer`. This is intentional because there is no initiating document. |
| Native page-initiated navigation through the normal HTTP transport | Uses `strict-origin-when-cross-origin`: the full source URL for same-origin requests, the source origin for cross-origin requests, and no header for HTTPS-to-HTTP downgrades. |
| Native HTML POST form submission through the normal HTTP transport | Uses the same default policy. |
| Scripted `fetch()` and `XMLHttpRequest` | The default `Referer` is currently omitted. This is tracked upstream in [issue #875](https://github.com/h4ckf0r0day/obscura/issues/875). |
| Page-initiated GET navigation with `--stealth` | The default `Referer` is currently omitted because the navigation source is not propagated into the stealth request profile. |

`Referrer-Policy` response-header and element-level overrides are not yet
plumbed through the navigation request path. The implemented native-navigation
behavior therefore uses the default policy above.

## Impact

Applications that require a same-origin or origin-only `Referer` may reject
scripted API requests or stealth GET navigations even though the visible page
rendered and input events succeeded. A server error about a missing referrer is
not, by itself, enough to identify the affected path: capture the request
method, initiator class, redirect chain, and received headers in a reduced
reproduction.

Do not work around this by adding a static `Referer`. An unconditional full URL
can leak paths or credentials cross-origin, and a header must not be sent on an
HTTPS-to-HTTP downgrade.

## Tracking and verification

Follow [issue #875](https://github.com/h4ckf0r0day/obscura/issues/875) for the
scripted `fetch()`/XHR fix. Until upstream behavior changes, distinguish these
cases in compatibility reports:

- direct automation navigation: expected omission;
- scripted `fetch()`/XHR: known limitation;
- page-initiated stealth GET navigation: known limitation;
- native POST form submission: expected to include the policy-derived header;
  capture wire evidence before reporting a regression.

A complete regression check should use a loopback server and assert the
received header for same-origin, cross-origin, and HTTPS-to-HTTP downgrade
requests in both normal and stealth modes. Browser protocol metadata such as a
reported `referrerPolicy` value is not proof that the wire request contained the
header.
