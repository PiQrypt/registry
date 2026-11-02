# Verifying the PiQrypt ambassador chain

The ambassador agent (u/piqrypt on Moltbook) signs a record of what it does: every comment, reply, post
and upvote becomes an event, signed with the agent's Ed25519 key and linked to the event before it by
hash. A snapshot of that chain is published in the registry (`ambassador/chain/latest.pqz`, plus one
dated file per day). `verify_ambassador.py` checks a snapshot from the file alone: no account, no
server, nothing to trust but the file and the code, which is one short file using the standard library.

## Run it

```
pip install cryptography            # or pynacl; without one, signatures are not checked
python verify_ambassador.py         # fetches the latest published snapshot
python verify_ambassador.py --chain latest.pqz --expect-agent pq1_8b3e1fae2be81e5fe3cdf5d15f98d4db
```

To check a comment, save its text exactly as shown on Moltbook, last line included, and add
`--comment-file comment.txt`. A comment ends with a line like `[sha256:30ff4eb20a78]`: the first 12 hex
characters of the SHA-256 of the text above it (stripped of surrounding whitespace). You can check that
part by hand, without the tool:

```
printf '%s' "<the comment without its last line>" | sha256sum        # first 12 characters
```

The chain event for that comment carries the full hash (`content_hash`). The tool finds it, checks the
event's hash and signature, and tells you whether it sits on the main line of the chain and how many
events were stamped after it. Exit status: 0 PASS, 1 FAIL, 2 file unreadable, 3 PARTIAL.

## What a PASS means

- The agent id is the SHA-256 of the public key in the file (`pq1_` + the first 32 hex characters).
- `export_hash` matches the events, so the file is the one that was exported.
- The events form one chain: a single first event, every event's `previous_hash` is the hash of another
  event of the file.
- Each event that carries its signed body (`event_json`) has the hash it claims (SHA-256 of the
  canonical JSON of the event without its signature), the `previous_hash` and timestamp of the table
  row, and a valid Ed25519 signature by the key above.
- For a comment: the text matches its suffix, and a verified event on the main line carries its hash.

## What it does not mean

- **The key holder is who they say.** The agent id proves a signature came from one key, nothing about
  who holds it. The check is only as independent as the channel the id came from: get it somewhere other
  than this file (the agent's profile, a post, the project site) and pass it with `--expect-agent`.
- **The time is true.** Timestamps are declared by the signer. They are not yet anchored to an outside
  clock (RFC 3161 timestamping is available in PiQrypt Pro and is not used for this chain).
- **Nothing is missing.** A signer can stop publishing, or publish a chain that ends earlier. Keep the
  head hash you saw (and the date): a later snapshot must contain it. The registry's commit history shows
  when each snapshot was committed, but it is controlled by the same operator.
- **The post exists on Moltbook.** A matching event shows the key signed that text. It does not show the
  text was posted, or by which account.
- **Old events were kept without their signed body.** Before the version that introduced `event_json`,
  the table kept only hashes and signatures: those events are linked into the chain, but their signatures
  cannot be re-checked and a comment from that period cannot be matched to its event. The tool says how
  many events are in that state, and answers PARTIAL when a snapshot holds no signed body at all.

## Known history of the two published chains

Read from the registry on 2026-11-02; every figure can be reproduced by running the tool on the dated files.

- **Chain 1**: first event 2026-04-16 13:18 UTC, last snapshot 2026-05-13 (`2026-05-13.pqz`): 1678
  events, head `e63d2e292a77c3bded1cf4b9cc2d79988077ad30c8934ca790e307a16caccf4a`.
- **Chain 2**: a new first event on 2026-05-17 20:13:39 UTC (`e44e41cf8c0fc854eb7583c478ab4b4c388a8f460e89f92feb5e9bc01eba1f70`),
  not linked to chain 1. The registry holds no snapshot from 2026-05-14 to 2026-05-17 and does not say
  why the chain started over. Last snapshot 2026-06-10: 1278 events, head
  `9b407f17b8c124d4dd5f9c21fad5f519a7ee4f39c529402dcad815acd6ed3967`.
- **No snapshot between 2026-06-10 and the next one**: events stamped in that period are not in the
  registry until a new snapshot is published. A signed continuity statement (`chain_continuity_statement`)
  records what the chain held when publishing resumed and names the previous chain.
- **Forks.** Both chains contain forks: an event named as `previous_hash` by two events (224 in chain 1,
  184 in chain 2). The tool prints their number. In every one, the parent was stamped in the same second
  as the first of its two children (an upvote right after a comment). The head lookup compared whole
  seconds and returned the older of the two events, so the next event was chained to the parent instead
  of the tip. The lookup was corrected (see the CHANGELOG); the forks already in the chains stay, and
  the sibling that lost each fork is a side event, still signed and still linked.
- **The one human decision.** On 2026-05-31 18:36:49 UTC the server declared a chain break
  (`5ce86135-294a-4d35-b55f-0ecfaf13d6fa`, first break at 1779048836 = 2026-05-17 20:13:56 UTC, the first
  fork of chain 2); an administrator validated it at 18:41:09 UTC, and the signed `chain_break_resolution`
  event is in the chain. That decision covers this record. The other forks have the same shape and were
  not reviewed one by one.
