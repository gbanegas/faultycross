# LESS Fault 

---

## Idea

The main idea is:

- the normal implementation builds a seed tree, derives one seed per signing round, commits to round data, derives a challenge, and then reveals only part of the tree in the signature;
- the fault harnesses corrupt the seed tree at different moments;
- the verification result then tells you whether the corruption hit a part of the tree that matters to the published portion of the signature.

The most important lesson is that **fault timing matters**:

- if the tree is corrupted **before** the digest/challenge is fixed, the fault often just produces a **different but still valid signature**;
- if the tree is corrupted **after** the digest is fixed but **before** the published seeds are extracted, the fault can become a **safe-error oracle**.

---


## How signing works in this code

At a high level, signing does the following:

1. Expand the secret key seed and derive internal seeds.
2. Generate an ephemeral root seed for the current signature.
3. Build a **GGM seed tree** from that root using `BuildGGM(...)`.
4. Extract the `T` leaf seeds using `seed_leaves(...)`.
5. For each of the `T=192` rounds:
   - derive a round object from the round seed and salt;
   - compute commitment-like data.
6. Hash all commitments to obtain `sig->digest`.
7. Derive the challenge from that digest using `SampleChallenge(...)`.
8. According to the challenge:
   - publish the appropriate seed path via `GGMPath(...)` into `sig->seed_storage`;
   - include `W=36` response objects in `cf_monom_actions`.

So the seed tree controls **which per-round randomness is opened** and which parts remain hidden.

---

## How verification works

Verification reverses the process:

1. Recompute the challenge from `sig->digest`.
2. Rebuild the needed leaves from the published seed path using `RebuildGGM(...)`.
3. Recompute the round commitments/responses.
4. Recompute the digest.
5. Accept only if the recomputed digest matches the signature digest.

This is why the seed tree is such a sensitive fault target: if you corrupt the wrong node at the wrong time, verification fails; if you corrupt it earlier, the whole signature may simply shift consistently to a different valid instance.

---

## Where the fault-related code is

There are **three** files you should focus on.

### `lib/test/fault_analysis.c`
This is the easiest file to read first.

It is an **inspection/debug harness** that:

- runs keygen/sign/verify;
- prints parameters;
- prints the full GGM tree;
- prints the leaf seeds;
- dumps the signature fields;
- shows the sizes and layout of the signature.

This file is mostly for understanding, not attacking.

### `lib/test/fault_inject.c`
This is the first actual fault campaign.

It injects faults **during tree generation**, by replacing the normal tree expansion with a modified one:

- `BuildGGM_faulted(...)`
- `LESS_sign_faulted(...)`

It then compares the faulted signature to a golden reference and records whether:

- verification still succeeds;
- the digest changed;
- the seed storage changed;
- the fault affected a subtree that contains published leaves.

### `lib/test/post_commit_fault.c`
This is the most interesting attack file.

It injects a fault **after the digest is already computed** but **before** `GGMPath(...)` extracts the published seeds. This is a much stronger and cleaner attack point.

This file explicitly implements the safe-error logic:

- if faulting a node still verifies, all relevant descendants were hidden/withheld;
- if faulting a node breaks verification, at least one relevant descendant was published.

### `lib/test/post_commit_v2.c`
A variant or extension of the post-commitment analysis. It belongs to the same family of experiments.

---

## The exact fault models used in `fault_inject.c`

The code defines several injected fault models:

- `FAULT_NONE`
- `FAULT_SKIP_EXPAND`
- `FAULT_BITFLIP`
- `FAULT_ZERO_SEED`
- `FAULT_WRONG_DS`

Meaning:

- **skip expand**: do not derive the children normally;
- **bitflip**: flip a bit in the parent seed;
- **zero seed**: overwrite the parent seed with zeros;
- **wrong DS**: corrupt the domain-separation index used for expansion.

These are controlled by global variables such as:

- `g_fault_target_node`
- `g_fault_model`

So the harness chooses one tree node and one fault model, signs once, then checks the result.

---

## The two fault timings, and why they matter

This is the most important conceptual part of the whole archive.

### Model A: fault during `BuildGGM`
Implemented in `fault_inject.c`.

The fault happens **before** the commitment hash is finalized.

That means:

- the leaf seeds change;
- the commitments change;
- the digest changes;
- the challenge changes too.

So very often the result is not an invalid signature. Instead it is simply a **different valid signature**.

That is why the file often observes behavior like:

- verify = success
- signature differs from golden
- digest differs from golden

This is a **differential effect**, not yet a clean safe-error oracle.

### Model B: fault after the digest, before `GGMPath`
Implemented in `post_commit_fault.c`.

The fault happens **after** the digest is fixed and the challenge is already determined.

Now the situation is very different:

- the challenge does **not** change anymore;
- only the seed path extracted into the signature is corrupted;
- verification outcome now tells you whether the corrupted subtree intersects the published/opened leaves.

This is exactly the safe-error setting the code is trying to expose.

---

## What the code means by “published” and “withheld”

The challenge is sampled as a fixed-weight string over `T=192` positions, with `W=36` selected positions.

In the code’s logic:

- some positions have their seed information **published/opened** through the GGM path;
- the other positions are **withheld** and instead represented through `cf_monom_actions`.

This is the important implication for the fault attack:

- if a corrupted subtree contains only **withheld** leaves, the corruption may stay invisible to verification;
- if it contains at least one **published** leaf, the extracted seed path becomes inconsistent and verification fails.

That gives an oracle about the hidden challenge structure.

---

## What the output files show

### `fault_results.csv`
This records the campaign from `fault_inject.c`.

The columns include:

- `node`
- `level`
- `fault_model`
- `verify_result`
- `sig_matches_golden`
- `digest_matches`
- `seeds_match`
- `num_descendant_leaves`
- `descendant_published`
- `descendant_withheld`
- `leaked_info`

A typical row from the beginning looks like this idea:

- verification succeeds,
- but the faulted signature is not equal to the golden one,
- and the digest changed.

This confirms the key point: **pre-commitment faults often give a new valid signature rather than a direct safe-error signal**.

### `post_commit_analysis.txt`
This file summarizes the post-commitment model.

It prints:

- the challenge,
- for each node: how many descendant leaves it covers,
- how many descendant leaves are published or withheld,
- whether it qualifies as a safe-error candidate.

This file is directly aligned with the safe-error interpretation.

---

## What you learn from the code

### Lesson 1: the target is the GGM seed tree
The fault attack is not randomly poking the scheme. It specifically targets the structure that decides **which round seeds are reconstructible from the signature**.

### Lesson 2: timing dominates fault usefulness
The same corruption can have very different meanings depending on whether it occurs:

- before commitments are hashed, or
- after the digest/challenge is fixed.

### Lesson 3: pre-commitment faults are often “too early”
If you fault too early, the signer simply signs a different internal state consistently. This often produces a different valid signature, which is less useful as an oracle.

### Lesson 4: post-commitment faults can become a safe-error oracle
If you fault after the challenge is fixed, the verification result can reveal whether a subtree intersects the published portion of the challenge.

### Lesson 5: challenge sparsity matters
For `LESS-252-192`, the challenge has only `W=36` selected positions out of `T=192`. That sparsity is exactly what makes subtree reasoning meaningful.

### Lesson 6: the harness is both experimental and educational
The repository is useful not only to test attacks, but also to understand:

- how a seed tree is built and traversed,
- how signing and verification consume the tree,
- how fault timing changes the observable behavior.

---

## A small terminology warning

One confusing point in the attack code is that some variable names can suggest “publish” even when the flag convention is closer to “withhold” or “open vs not open”.

So when reading the code, do not rely only on variable names. Track what the function actually does:

- `GGMPath(...)` extracts the seeds that will be stored in `sig->seed_storage`;
- `RebuildGGM(...)` reconstructs what the verifier can recover from that storage.

The real semantics come from those functions, not from the local variable name alone.

---

## Recommended reading order

If you want to understand the repo efficiently, read it in this order:

1. `include/parameters.h`
2. `include/LESS.h`
3. `lib/seedtree.c`
4. `lib/LESS.c`
5. `lib/test/fault_analysis.c`
6. `lib/test/fault_inject.c`
7. `lib/test/post_commit_fault.c`
8. `lib/test/post_commit_v2.c`
9. `fault_results.csv`
10. `post_commit_analysis.txt`

This order goes from:

- parameters,
- to data structures,
- to the seed tree,
- to sign/verify,
- and only then to the fault experiments.

---

## How the CMake file organizes the binaries

The `CMakeLists.txt` builds:

- benchmarks for many parameter sets;
- normal test binaries;
- NIST KAT generators;
- dedicated fault binaries for `LESS-252-192`:
  - `LESS_fault_analysis`
  - `LESS_fault_inject`
  - `LESS_post_commit_fault`
  - `LESS_post_commit_v2`

So the fault attack code is not mixed invisibly into the normal implementation. It is exposed as separate test/analysis executables.

---



