## General

A DATUM pool tells the Gateway a minimum share difficulty, and by default the Gateway raises
every miner to it. Some pools size that minimum to the Gateway's *total* share rate, so behind
a busy Gateway each miner is asked for a difficulty sized for the whole fleet rather than for
itself. A small miner then finds a share only every few minutes. For a miner rented from a
marketplace that matters: the marketplace measures delivered hashrate from accepted shares, so
its reading turns choppy, the rig's owner is warned that the pool's difficulty is too high, and
some marketplace proxies reconnect a pool that has gone a couple of minutes without accepting
a share.

`stratum.vardiff_below_pool_min` lets each miner keep a difficulty that suits it, without
changing what the pool receives:

```json
"stratum": {
	"vardiff_below_pool_min": true
}
```

It is off by default. With it off, miners are raised to the pool's minimum as before. Two
vardiff fixes from the same change apply either way: vardiff measures the rate at the
difficulty it now serves (a share from an older, easier job is accepted, credited at the
served difficulty if it meets it and otherwise without credit, and not counted toward the
rate as if it were at the new one), and it starts measuring afresh whenever it sends a new
difficulty.

## What changes

For pooled work, every job now has two difficulties:

| | Set from | Used for |
| --- | --- | --- |
| **Served** | the miner's own vardiff (and `d=`/`fd=` when `stratum.password_difficulty` is on) | `mining.set_difficulty`, and the Gateway's local acceptance of the miner's shares |
| **Committed** | the served difficulty, but never below the pool's minimum | the coinbase target byte the pool checks a share against (on BLAKE2b also the work commitment and its ABW bits) |

Without the option the two are always equal. With it, the served difficulty may be lower.

Every share that meets the served target is accepted, so the miner's delivered hashrate is
measured accurately, and vardiff and the idle timeouts see its real share rate. **Only shares
that also meet the committed target are sent to the pool.**

## Why the pool's credit is unchanged

Whether a hash meets the committed target does not depend on which difficulty the miner was
asked for. The shares forwarded are exactly the ones a miner working at the committed
difficulty would have found, with the same expected credit and the same variance. Blocks are
among them, since a block meets any share target up to the network's. Nothing is withheld; the miner only reports
the easier shares in between, which the Gateway keeps to itself.

The pool sees no difference: each forwarded share carries the committed target, as before.

## Details

- **Quickdiff.** On BLAKE2b, a quickdiff job is new work only because its committed target
  byte differs from the job the miner already holds. When the commitment is held at the pool
  minimum and a quickdiff only raises the served difficulty, the Gateway sends just the new
  `mining.set_difficulty` and leaves the miner on its current job, rather than resending
  identical work that the miner would redo and resubmit as duplicates. The same goes when a
  newer job is still on its way to the miner: it arrives once, as a regular job at the new
  difficulty. On SHA256 a quickdiff job is already made unique by the marker at the end of
  coinb1, so nothing changes there.
- **Shares kept local.** A share between the two targets is accepted but not sent to the pool,
  except when the pool would take no share for its job: under anti-withholding, one with an
  assignment already disclosed is answered as stale, and one without an assignment is refused,
  as a forwarded share would be.
- **Password difficulty.** With `stratum.password_difficulty` on, a `d=N` below the pool's
  minimum is now served, where before the minimum overrode it. Rental tools can therefore ask
  for each rig's own optimal difficulty and get it. A fixed `fd=N` below the minimum is still
  raised to it, as before: with vardiff off, nothing else would keep a fixed low difficulty
  from becoming a flood of shares.
- **Not pooled.** Work that is not pooled (the pool is unreachable and the Gateway is mining
  solo) has no pool minimum, so the two difficulties are equal.

## datum.capabilities

Tools that point miners at a Gateway can ask what it supports. This is not a Stratum standard
method, and it needs no subscribe or authorize:

```
{"id":1,"method":"datum.capabilities","params":[]}
```

```json
{"error":null,"id":1,"result":{
	"gateway":"v0.5.0-beta","algo":"blake2b",
	"features":{"vardiff_below_pool_min":true,"password_difficulty":true,"reject_tls_probe":true},
	"pooled":true,"pool_min_diff":1048576}}
```

A feature listed with `false` is supported but switched off. A Gateway without the method
answers `Method not found`, which means none of these features. `pool_min_diff` is the pool's
current minimum as DATUM's integer difficulty (on BLAKE2b, `mining.set_difficulty` sends 65535/65536
of it), or `0` when not mining pooled. Send `"params":[]`: as with any request, one without
`params` closes the connection.

## TLS probes

A connection is closed at once when a read starts with a TLS handshake record (`0x16`) and no
partial line is pending, as at the start of a connection.
Some pool checkers, MiningRigRentals' among them, try encrypted stratum first; left waiting,
they time out and report a working plain-stratum pool as failing.
