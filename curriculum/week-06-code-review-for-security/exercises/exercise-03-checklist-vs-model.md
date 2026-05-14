# Exercise 3 — Checklist vs. Model

**Estimated time:** 90 minutes. The C6 short checklist (Lecture 3 § 6). A scratch text editor.

```
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZED USE ONLY                                                │
│                                                                     │
│  The target PR is synthesised; the patterns it contains are drawn   │
│  from public CVEs and audit reports. Do not run the snippets        │
│  against any deployed service. The exercise is reading and          │
│  commenting only.                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Scenario

You will review the **same PR twice**, with two different methods, recorded as two separate documents:

- **Review A — Checklist-only.** Walk the C6 short checklist (Lecture 3 § 6). Comment on every unchecked item that applies. Do not build a model; do not pattern-match outside the checklist items.
- **Review B — Model-only.** Build the input/sink/trust model (Lecture 3 § 2). Comment on every finding the model surfaces. Do not consult the checklist; do not pattern-match (except as the model itself dictates).

After both reviews, compare them. The disagreement set is the lesson.

This exercise covers:

- **Checklist-based review** in isolation (Lecture 3 § 1).
- **Model-based review** in isolation (Lecture 3 § 2).
- The **decision rule** for when each applies (Lecture 3 § 3).

---

## The target PR

The PR below is synthesised. It is approximately what an unfamiliar PR queue produces on a typical Friday afternoon.

### PR description (as the author wrote it)

> **PR #842 — Add `/teams/<team_id>/invite` endpoint and bulk-invite background job**
>
> *This PR adds a new endpoint that lets a team owner invite users to their team by email. The endpoint accepts a list of email addresses, validates each, sends an invitation email, and persists the invitation record in the DB. For lists with more than 50 emails, the work is offloaded to a Celery task. The invitation token is a signed URL with a 7-day expiry; the signing uses the existing `INVITE_SIGNING_KEY` config.*
>
> Files changed:
> - `app/routes/teams.py` (+62 / -3)
> - `app/services/invites.py` (+88 / -0)
> - `app/tasks/invite_bulk.py` (+34 / -0)
> - `app/models/invite.py` (+15 / -2)
> - `app/templates/email/invite.html` (+22 / -0)
> - `app/util/signing.py` (+18 / -4)
> - `tests/test_invite.py` (+74 / -0)
> - `requirements.txt` (+1 / -0)

### The relevant diff hunks

```python
# app/routes/teams.py, lines 102-138
+@teams_bp.route("/teams/<int:team_id>/invite", methods=["POST"])
+@login_required
+def team_invite(team_id):
+    team = Team.query.get_or_404(team_id)
+    emails = request.json.get("emails", [])
+    if not isinstance(emails, list):
+        abort(400, "emails must be a list")
+    if len(emails) > 50:
+        # Offload to Celery
+        invite_bulk.delay(team_id=team_id, emails=emails,
+                          invited_by_id=current_user.id)
+        return jsonify({"ok": True, "queued": len(emails)})
+    for email in emails:
+        send_one_invite(team, email, current_user)
+    return jsonify({"ok": True, "sent": len(emails)})
+
+
+def send_one_invite(team, email, inviter):
+    token = sign_invite(team_id=team.id, email=email,
+                        inviter_id=inviter.id,
+                        expires_at=(datetime.utcnow()
+                                    + timedelta(days=7)))
+    invite_link = f"https://{current_app.config['DOMAIN']}/invite/accept?t={token}"
+    body = render_template("email/invite.html",
+                           inviter=inviter, team=team,
+                           link=invite_link)
+    smtp_send(to=email, subject=f"Invitation to join {team.name}",
+              body=body)
+    Invite(team_id=team.id, email=email,
+           inviter_id=inviter.id, token=token).save()
```

```python
# app/util/signing.py, lines 12-30
-def sign_invite(team_id: int, email: str, expires_at: datetime) -> str:
+def sign_invite(team_id: int, email: str, inviter_id: int,
+                expires_at: datetime) -> str:
     payload = {
         "team_id": team_id,
         "email": email,
+        "inviter_id": inviter_id,
         "expires_at": expires_at.isoformat(),
     }
-    raw = json.dumps(payload).encode()
-    sig = hashlib.sha256(raw + current_app.config["INVITE_SIGNING_KEY"]).hexdigest()
+    raw = json.dumps(payload).encode()
+    sig = hashlib.sha256(raw + current_app.config["INVITE_SIGNING_KEY"]).hexdigest()
     return base64.urlsafe_b64encode(raw + b"." + sig.encode()).decode()
```

```python
# app/tasks/invite_bulk.py, lines 1-34
+from celery import shared_task
+from app.services.invites import send_one_invite
+from app.models import Team, User
+
+@shared_task
+def invite_bulk(team_id: int, emails: list, invited_by_id: int):
+    team = Team.query.get(team_id)
+    inviter = User.query.get(invited_by_id)
+    for email in emails:
+        send_one_invite(team, email, inviter)
```

```python
# app/templates/email/invite.html
+<html>
+  <body>
+    <p>Hi,</p>
+    <p>{{ inviter.name }} has invited you to join the team
+       <strong>{{ team.name }}</strong>.</p>
+    <p><a href="{{ link }}">Accept invitation</a></p>
+    <p>(If you did not expect this, ignore the email.)</p>
+  </body>
+</html>
```

```diff
# requirements.txt
+ flask-mail==0.9.1
```

```python
# tests/test_invite.py, lines 1-74
+def test_invite_happy_path(client, team_owner):
+    response = client.post(f"/teams/{team_owner.team.id}/invite",
+                           json={"emails": ["alice@example.com"]},
+                           headers={"Cookie": f"session={team_owner.session}"})
+    assert response.status_code == 200
+    assert response.json["ok"] is True
+    assert Invite.query.count() == 1
+
+def test_invite_bulk(client, team_owner):
+    emails = [f"user{i}@example.com" for i in range(60)]
+    response = client.post(f"/teams/{team_owner.team.id}/invite",
+                           json={"emails": emails},
+                           headers={"Cookie": f"session={team_owner.session}"})
+    assert response.status_code == 200
+    assert response.json["queued"] == 60
```

---

## Step 1 — Review A: Checklist-only (35 min)

Open `review-checklist.md`. Open the C6 short checklist (Lecture 3 § 6). Walk every item. For each item, record one of: `✓` (the PR satisfies it), `✗` (the PR violates it — comment), or `N/A` (the item does not apply to this PR).

Do **not** model the data flow; do **not** pattern-match beyond what the checklist items literally say. The discipline is to run the checklist *cold*.

Template:

```markdown
# Review A — Checklist-only

## Checklist walk

- C-1 Schema-validated entry point: ✗ — `emails = request.json.get("emails", [])`
   is a list of strings with no per-element schema. The `isinstance(emails, list)`
   check is bounded only at the type level. (Comment: `app/routes/teams.py:106` —
   apply a pydantic schema or `marshmallow` validator for the email shape.)
- C-2 Size-bounded input: ✗ — `len(emails) > 50` triggers offload but does not
   refuse oversize. An attacker can send 10,000 emails and the Celery worker will
   loop. (Comment: ...)
- C-3 No new pickle/yaml.load/etc.: ✓
- C-4 HTML output auto-escaped: ✓ — `render_template` is used.
- C-5 SQL parameterised: ✓ — ORM only.
- C-6 Subprocess args as list, shell=False: N/A.
- C-7 File-write Path.resolve + prefix: N/A.
- C-8 Outbound HTTP allow-list: N/A (SMTP send, not HTTP).
- C-9 State-changing route + ownership check: ✗ — `@login_required` is present
   but there is no check that `current_user` owns the team
   (`team.owner_id == current_user.id` or membership-with-invite-perm).
- ...
- ...

## Findings summary (from the unchecked items)

| ID | Item | CWE | Severity |
|----|------|-----|----------|
| F-A-1 | C-1 schema | CWE-20 | major |
| F-A-2 | C-2 size | CWE-770 | major |
| F-A-3 | C-9 authz | CWE-863 | blocking |
| ... | ... | ... | ... |
```

The checklist will surface most of the *obvious* findings. It will miss the design-level findings; that is by design.

---

## Step 2 — Review B: Model-only (35 min)

Open `review-model.md`. Build the input → sink → trust model (Lecture 3 § 2 steps 1-6). Write the model first, *as a paragraph*, then derive findings from it.

Template:

```markdown
# Review B — Model-only

## The model

### Where does data enter (post-diff)?

- The HTTP POST body — `emails`, `team_id` (URL).
- The session cookie — `current_user`.
- The DB — `Team.query.get`, `User.query.get`.
- The Celery queue — `invite_bulk` is invoked with `(team_id, emails,
   invited_by_id)` arguments; the queue is internal but the data on it
   originated from the web handler above.

### Where does data leave (post-diff)?

- The DB — `Invite.save()`.
- The SMTP outbound — `smtp_send(to=email, ...)`.
- The HTML email body — `{{ inviter.name }}`, `{{ team.name }}`, `{{ link }}`.
- The signed URL — `token` is sent in plaintext to whichever address is on
   the `emails` list.

### Trust levels (post-diff)

- `request.json["emails"]`: fully attacker-controlled.
- `team_id` (URL): attacker-controlled but bounded to integers by `<int:team_id>`.
- `current_user`: trusted (post-login).
- `team`: trusted (DB read, but ownership not yet checked against `current_user`).
- `inviter`: trusted as an authenticated user, but *not* validated as the owner
   of the team. Inviter and team can mismatch.

### Validators on the path

- `isinstance(emails, list)` at the route — bounds the *outer* type, not the
   element type.
- No email-shape validator (RFC 5322 or simpler regex).
- No team-ownership validator on the inviter.
- No rate-limit on the route.
- No size cap above 50 (the threshold offloads but does not refuse).
- `sign_invite` produces a token but the "signature" is a SHA-256 of
   `(payload || key)` — a *hash-with-key* construction, not an HMAC. It is
   vulnerable to length-extension on Merkle-Damgård (SHA-256 is vulnerable
   to length extension; SHA-512/256 and SHA-3 are not).

### Failure modes of each validator

- The `isinstance` check accepts a list of non-strings (`[{"a": "b"}]`)
   which then go to `email.lower()` or to `smtp_send` and fail in opaque
   ways or — depending on `smtp_send` — get logged with the malformed value.
- The missing email regex means the route can be coerced into sending mail
   to addresses controlled by the attacker, including those that match
   security-relevant aliases (`postmaster@target.com`, `security@target.com`)
   — see § 7 below.
- The missing team-ownership check means *any authenticated user* can invite
   strangers to *any* team they did not create.
- The hash-with-key signature can be extended: an attacker who has *one*
   valid token can produce a *different* valid token for a different payload
   without knowing the key. CVE-2009-2945 (Flickr), CVE-2014-7191 (Node.js
   `tweetnacl`) are precedents.

### What does the failure do?

- Email-injection: target's MTA logs a flood of inbound; reputation damage.
- Authorization bypass: attacker invites themselves to any team in the DB.
- Length-extension: attacker forges invites with arbitrary `team_id` and
   `email` without knowing the signing key, defeating the entire invite
   mechanism.

## Findings derived from the model

| ID | Hazard | CWE | Severity |
|----|--------|-----|----------|
| F-B-1 | Hash-with-key signature, length-extensible | CWE-345, CWE-916 | blocking |
| F-B-2 | Missing team-ownership check | CWE-863, CWE-639 | blocking |
| F-B-3 | No email shape validation | CWE-20 | major |
| F-B-4 | No upper bound on `emails`; Celery DoS | CWE-770 | major |
| F-B-5 | No rate-limit on invite endpoint | CWE-307 | major |
| F-B-6 | Token sent over email in plaintext (acceptable, but flag) | N/A | nit |
```

The model surfaces findings the checklist misses — most importantly the *cryptographic* finding (the hash-with-key is not HMAC). A reviewer who knows what HMAC is for, and who reads the signing code carefully, sees CVE-2009-2945-shape immediately; a reviewer who only walked the checklist would see "C-13 secret comparison constant-time? — N/A here, signing is one-way" and miss it.

---

## Step 3 — Compare (15 min)

Open `comparison.md`.

```markdown
# Comparison

## Findings only the checklist found

(List F-A-N entries that have no F-B-N counterpart.)

| F-A-N | Why model missed |
|-------|------------------|
| F-A-X | <one sentence — what about the model's framing did not surface this> |
| ... | ... |

## Findings only the model found

(List F-B-N entries that have no F-A-N counterpart.)

| F-B-N | Why checklist missed |
|-------|----------------------|
| F-B-X | <one sentence — which checklist item *should* have covered this, and why
            its phrasing did not> |
| ... | ... |

## Findings both methods found

| F-A-N == F-B-N | Hazard | Notes |
|----------------|--------|-------|
| ... | ... | ... |

## Reflection (200-400 words)

1. Which method felt faster?
2. Which method felt more thorough?
3. Which findings would you have missed running only the method that did not catch
   them?
4. What change would you make to the C6 short checklist to close the gap?
5. What change would you make to your *personal* checklist after this exercise?
```

The reflection is the artifact. The exercise is not graded on which method "won" — both have gaps, and the discipline is to use both. The reflection answers the question *which gap will you close*.

---

## Step 4 — Update your personal checklist (5 min)

If the exercise surfaced a finding that neither the C6 short checklist nor your model framing would have caught (e.g., the hash-with-key is genuinely subtle if you have not seen the construction before), add the item to your personal checklist:

```markdown
# review-checklist.md (personal)

(Existing items from C6 short checklist, copied.)

## Additions

- [ ] P-1 Every "signed URL" or "signed token" uses HMAC (`hmac.new(key,
       payload, sha256).digest()`), not `hashlib.sha256(payload + key)`.
       Reference: CWE-345, CWE-916, length-extension class.
- ...
```

Commit `review-checklist.md` to your portfolio repo. Iterate it after every real review.

---

## Acceptance criteria

The exercise is complete when:

- [ ] `review-checklist.md` walks every C6 short checklist item with `✓` / `✗` / `N/A` and a one-sentence justification for each ✗.
- [ ] `review-model.md` contains the input/sink/trust paragraph and the derived findings table.
- [ ] `comparison.md` contains all three tables (checklist-only, model-only, both) and a 200-400 word reflection.
- [ ] `review-checklist.md` (the personal one) has been updated with at least one new item, if the exercise revealed a gap.
- [ ] The reviewer noticed the hash-with-key length-extension finding *somewhere*. (If neither review caught it, the reflection should explicitly say so and add it to the personal checklist.)

The exercise is *stronger* if:

- [ ] You have already done Exercise 1 against a real PR and you can compare the methods' relative usefulness in that real context.
- [ ] You picked up at least one method-level discipline you will use on the mini-project — e.g., "I will always build the input/sink/trust model on PRs that touch signing or hashing primitives."

---

## Notes on the hash-with-key finding

For learners who have not seen the hash-with-key vs. HMAC distinction before:

The construction in the diff —

```python
sig = hashlib.sha256(raw + key).hexdigest()
```

— is *not* HMAC and is *not safe* with SHA-256. SHA-256 (and SHA-1, MD5) are
Merkle-Damgård hashes; their state after processing `raw` is the SHA-256 of
`raw`, and an attacker with *one* `(payload, sig)` pair can compute a valid
`sig'` for `(payload || padding || extension)` *without knowing the key*,
where `padding` is the standard Merkle-Damgård glue. The classic exploit
predates by a decade the introduction of HMAC into general practice. HMAC's
key-XOR-then-hash twice construction blocks length-extension by design.

References to keep on hand:

- **HMAC RFC 2104.** <https://www.rfc-editor.org/rfc/rfc2104>.
- **Length-extension attack on Flickr API (CVE-2009-2945-shape, 2009).**
  Public write-up by Thai Duong and Juliano Rizzo.
- **Trail of Bits blog on cryptographic engineering** for related material.
- **Python `hmac` docs.** <https://docs.python.org/3/library/hmac.html>.
- **CWE-345 Insufficient Verification of Data Authenticity** —
  <https://cwe.mitre.org/data/definitions/345.html>.

The Python idiom is:

```python
import hmac, hashlib
sig = hmac.new(key, raw, hashlib.sha256).digest()
```

…and verification uses `hmac.compare_digest(received, computed)` for constant time.

This is the canonical "model catches what checklist misses" example. If neither your checklist walk nor your model paragraph surfaced it on the first pass, that is *itself the lesson* — add the item to the personal checklist and the model framing for next time.
