---
name: RFC 9421 @query-param encoding
description: How the @query-param derived component value must be encoded (percent-encoding, not '+')
---

# @query-param re-encoding (RFC 9421 §2.2.8)

Both the `;name=` identifier and the component value are the **percent-encoded**
forms of the decoded query parameter. A space becomes `%20` and a newline `%0A`
— **not** `+`. The RFC examples show source `with+plus+whitespace` →
`with%20plus%20whitespace` and a multiline value → `this%20is%20a%20big%0A...`.

**How to apply:**
- Iterate `url.searchParams` (this yields the *decoded* name/value — form parsing
  step 1), then re-encode both with `encodeURIComponent` (step 2). Do **not** use
  `URLSearchParams.toString()` or any form-urlencoder that emits `+` for spaces.
- Match on the *re-encoded* name; emit the *re-encoded* value. Keep the first
  occurrence of a repeated name. A name not present is an error.

**Why:** an earlier implementation used a `+`-emitting form encoder, which
produces a different signature base than every other RFC-conformant
implementation, so cross-implementation verification silently fails.
