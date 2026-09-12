# Production SNS delivery verification — 2026-09-12

The existing topic `layrs-production-operational-alerts` now has an active
email subscription for `layrs.support@predifi.com`.

The subscription was confirmed through the existing SNS confirmation flow with
`AuthenticateOnUnsubscribe=true`.  A controlled non-financial delivery test
was published as `Layrs SNS delivery verification 20260912` and independently
observed in the Predifi catch-all Gmail inbox.  The subscription remained
active after observation and no unsubscribe confirmation was received.

This did not create a notification system, move funds, change custody,
enable a writer, or execute a canary.
