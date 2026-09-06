# Multiple access tokens in one grant

GNAP lets a client request separate access tokens in one grant. Each requested
token has a unique label. The authorization server can approve a subset, keeping
each issued token under its requested label. A missing token is omitted, not
replaced by a union of its rights with those of another token. See RFC 9635
[§2.1.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1.2) and
[§3.2.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2.2).

## Selecting tokens in the AS policy

`Decision::ApproveTokens` selects requested slots explicitly. Each
`TokenApproval` contains the exact requested label and the rights approved for
that token alone. For an unlabelled singleton, `requested_label` is `None`.
Labels are opaque strings: the SDK does not normalize them.

For example, a policy can approve a `reports` token without approving the
`documents` token in the same request. It returns one `TokenApproval` for
`reports`. The response is still an array, because the request was an array;
the issued token keeps the `reports` label. Selection order does not matter:
this AS emits tokens in request order. Consumers must correlate by label.

The selection must contain between 1 and 64 tokens, with unique labels drawn
from the request. This is a bound on this SDK's policy output, not a GNAP limit
on request arrays. Invalid policy output produces a non-GNAP server failure
without issuing tokens. To refuse the grant or request consent, return `Deny`
or `RequireInteraction`; there is no per-label pending state.

The older `Decision::Approve` remains a compatibility path: it issues one token,
using the first requested slot. Policies that serve multiple resources should
use `ApproveTokens` to make the selection and separation of rights explicit.

## Publication and management

For an actual batch, the AS prepares every candidate value, management handle
and management credential, plus one continuation credential when the policy
keeps the grant open, before invoking an encoder. It checks collisions between
siblings and with the previous grant's credentials. Encoded values and native
identifiers must also be distinct. Collisions with other grants are checked by
the store at publication.

All selected tokens are published through one grant creation or
compare-and-exchange. An encoder failure on the second token does not publish
the first. A failed reapproval leaves the previous tokens and continuation
unchanged. This does not make arbitrary external side effects of a custom
encoder transactional; the encoder must not publish authority independently.

Each token has its own management endpoint and credential. Rotation or deletion
of one token does not renew or revoke its siblings. A successful PATCH
reapproval replaces the whole previous token set in this implementation.
Deleting the grant revokes all its tokens. These operations retain the
[atomic storage contract](../crates/gnap-as/src/storage.rs).

The [downstream derivation profile](downstream-delegation.md) tracks an exact
parent token, not just its grant. Revoking a sibling leaves a parent's derived
token intact. Removing or replacing the parent cascades to its derived token;
a stale compare-and-exchange cannot restore it.

## Current implementation boundaries

All tokens in a selected batch use the requesting client's key and the common
lifetime returned by the policy. This path does not issue bearer or durable
tokens, select different keys for individual tokens, or infer resource-server
audiences from labels. The deployment still has to authorize each token's
rights and enforce its intended audience.

The signed AS tests cover selection, partial approval, singleton cardinality,
credential and native-identifier collisions, encoder failure, targeted token
management, reapproval and exact-parent derivation cascades. They are local
protocol tests, not evidence of interoperability with another implementation
or of a deployed multi-resource application.
