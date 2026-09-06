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

The [reference application](../apps/delegation-demo/README.md) now exposes both
the original single-token flow and a two-token flow. Its resource-server roles
use distinct keys to authenticate introspection, but remain in one process:

| Token | Resource-server role | Key proving the resource request |
| --- | --- | --- |
| `documents` | RS1: document reads and the operation that obtains downstream metadata | Original client key |
| `reports` | RS3: the synthetic reports summary | Original client key |
| Derived metadata token, without a label | RS2: archive metadata only | RS1's own key |

Consent can approve both requested tokens or only `reports`. The browser keeps
its multiple-token mode even when only one token is held. Actions select by
label and fail locally when that token is missing; they never fall back to a
sibling. A PATCH is compared against each live token with the same label,
not the union of all the grant's rights. Requesting a previously omitted slot
therefore requires fresh consent. These are application policy decisions.

The socket-based [consumer tests](../apps/delegation-demo/src/multiple_tests.rs)
exercise the real client, AS, RS roles and browser worker. They cover full and
partial approval, cross-audience refusals, sibling management, derivation
cascades, consent after expansion and grant revocation. The browser's retired
token is stored together with its label so its check addresses the intended RS;
an audience refusal at another RS would not demonstrate retirement.

The client session retains the requested labels and rejects unknown or
contradictory response labels. It accepts partial and reordered responses.
Management by label selects a held token; omitting the label is allowed only
when exactly one token is held, including a labelled singleton.

During rotation the session preserves an omitted label and compares flags as
an unordered set. It refuses a new resource token whose value repeats either
the previous resource value or the credential used for that management call;
the latter comparison is explicitly required by RFC 9635 §6.1. Its key-binding
comparison is conservative: both key fields
must be absent or both must contain the same explicit representation. The
session cannot establish equivalence between an implicit client key and an
explicit key, or resolve two key references. A matching `kid` is not enough:
different keys can share that identifier. A representation change may therefore
be refused even when an external resolver could establish the same key. This
is a documented session limitation, not a new GNAP requirement.

All tokens in a selected batch use the requesting client's key and the common
lifetime returned by the policy. This path does not issue bearer or durable
tokens, select different keys for individual tokens, or infer resource-server
audiences from labels. The deployment still has to authorize each token's
rights and enforce its intended audience.

The signed AS tests also cover selection, partial approval, singleton cardinality,
credential and native-identifier collisions, encoder failure, targeted token
management, reapproval and exact-parent derivation cascades. They are local
protocol tests. The consumer adds co-located HTTP execution, not evidence of
interoperability with another implementation or of a separately deployed
multi-resource application.
