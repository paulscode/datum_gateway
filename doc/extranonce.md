## General

The BLAKE2b work root a hasher computes is

```
root = BLAKE2b-256( 0x00 || coinb1(39) || extranonce(12) )
```

a 52-byte leaf, of which the last 12 bytes are the hasher extranonce. Those 12 bytes are
fixed by consensus. What is *not* fixed is how they are divided between the part the
Gateway owns and the part the miner varies, because Stratum negotiates that split in the
`mining.subscribe` reply as an extranonce1 string and an extranonce2 size.

By default the Gateway serves a 4/8 split: a 4-byte extranonce1 carrying the session id,
and an 8-byte extranonce2. Every miner tested against this chain works that way, and it
is what you should leave this on.

**Always test your full mining stack configuration.**
Misconfiguration of either the DATUM Gateway or your miners *can* result in lost work
that is impossible to recover!

## Firmware with a 32-bit nonce2

Some Sia-lineage firmware has a 32-bit extranonce2 compiled in and will not accept an
8-byte one. The Obelisk SC1 Gen 2 (`ob2`, cgminer-sia 4.10.0) is the known case: it
checks the advertised size against 4 and rejects the job otherwise.

`stratum`.`extranonce2_size` moves the split to 8/4 for such firmware:

```json
"stratum": {
    "extranonce2_size": 4
}
```

It is also on the dashboard's **Config** page, as **Extranonce2 size**, for setups where
the config file is the source of truth and the dashboard is the settings form — set
`admin_password` and `modify_conf` in the `api` section to enable that. Changing it there
restarts the Gateway, which is what makes every connected miner reconnect and pick up the
new split.

Only `8` (the default) and `4` are accepted; anything else is refused at startup rather
than clamped, because a Gateway quietly serving a split the operator did not configure
is how a whole farm ends up rejected `H-not-zero`. The dashboard only offers the two, and
refuses anything else with an error rather than writing a config file that will not load
on the next boot.

The 12-byte field does not shrink. The session id is padded out to 8 bytes with four
zero bytes, and the miner's 4 bytes go in the low end:

| | bytes 0-3 | bytes 4-7 | bytes 8-11 |
| --- | --- | --- | --- |
| default 4/8 | session id | miner's extranonce2 | miner's extranonce2 |
| 8/4 | session id | zero padding | miner's extranonce2 |

So the miner still concatenates coinb1, extranonce1 and extranonce2 and still arrives at
a 52-byte leaf. Only the part it is free to vary gets smaller — from 2^64 values to
2^32, which is still far more extranonce space than a single connection can exhaust
between work updates.

This is a per-Gateway setting, negotiated once per connection at subscribe and held for
the life of that connection, so reloading the config does not change the split under a
miner that is already connected. It is *not* per miner: if you run 32-bit-nonce2
firmware alongside other hardware, either verify the other hardware on the 8/4 split
first, or run a second Gateway for it.

## Miners that submit a 32-bit nonce2 in an 8-byte field

Separately from the setting above, the Gateway tolerates firmware that accepts the
8-byte extranonce2 but only really has 32 bits of it. The SC1 Gen 2 does this when
patched to pass its size check: it hashes its work root over the value zero-padded to 8
bytes, but hex-encodes 8 bytes out of a 4-byte variable, so the high 4 bytes on the wire
are whatever was next to it in memory.

Read literally those bytes rebuild a different root, and every share comes back
`H-not-zero`. The Gateway reads the extranonce2 exactly as submitted first, and only if
that fails the `H-not-zero` gate does it retry with the high 4 bytes zeroed. A miner
whose shares reconstruct as submitted never reaches the retry, and once a connection has
proven it means all 8 bytes — by passing the gate on a share whose high bytes were not
zero — it is never reinterpreted again.

Nothing needs to be configured for this. The first share it rescues on a connection is
logged, with the miner's address and user agent:

```
Client 10.0.0.7/cgminer/4.10.0 submits a 32-bit extranonce2 in an 8-byte field;
zero-extending it for this connection.
```

If you see that line, the miner is mining correctly, but `extranonce2_size` of 4 is the
cleaner arrangement for it if the rest of your fleet can live on that split.
