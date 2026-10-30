// Aggregation + sandbox verdicts. Pure JS over the exec stream: it takes
// normalized exec records (see lib/argv.js), folds repetition into one row per
// kind of command, and pairs each command's net namespace with whether it
// touched something sensitive to say which side of the sandbox boundary it ran
// on.
//
// No BPF here by design. The same functions run against a recorded stream,
// which is how the verdict logic gets tested without a kernel.

// A "verb" is a subcommand that changes what the tool DOES (`git rev-parse`,
// `npm run`, `docker build`). Keeping it in the fold key stops `git gc` folding
// into `git log`.
//
// Only tools that actually have subcommands get this treatment. Applying it to
// everything was a real bug: `echo u1`, `echo u2` … each became its own fold,
// so fifty echoes read as fifty distinct commands instead of one row of ×50.
const VERBED = /^(git|npm|npx|yarn|pnpm|docker|podman|cargo|go|kubectl|systemctl|apt|apt-get|dnf|yum|pip|pip3|brew|make|gh|hg|svn)$/;
const isVerb = (a) => /^[a-z][a-z0-9-]{1,20}$/.test(a);

// `-DFOO=bar` and `-DFOO=baz` are the same flag; `-I/a` and `-I/b` likewise.
// Fold on the flag NAME, dropping any attached value.
const flagName = (a) => a.replace(/[=:].*$/, "").replace(/^(-[A-Za-z])(?=[^-]).*$/, "$1");

// A `sh -c` script's identity is the COMMAND it runs, not its text. Build
// systems generate a fresh script per target, so folding on the text shatters
// one recipe into dozens of one-off rows. Fold on the first real command word.
const shScriptFold = (script) => {
  const s = script.trim();
  // Comment-only recipe lines are real execs but carry no command at all.
  if (/^#/.test(s)) return "#comment";
  // Strip a leading `cd ... &&` / env assignments, then take the first word.
  const body = s
    .replace(/^\s*cd\s+[^&;|]+(&&|;)\s*/, "")
    .replace(/^(\s*[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+)+/, "");
  const first = body.split(/[\s;|&(]+/).find(Boolean) ?? "";
  return first.replace(/^.*\//, "") || "?";
};

const isShellC = (comm, rest) =>
  /^(sh|bash|dash|zsh)$/.test(comm) && rest.includes("-c");

export const foldKey = (e) => {
  const rest = e.argv.slice(1);
  if (isShellC(e.comm, rest))
    return e.comm + " -c " + shScriptFold(rest[rest.indexOf("-c") + 1] ?? "");
  // Dedupe: a compiler line carries `-I` once per include path, and `-I a -I b`
  // vs `-I a -I b -I c` are the same KIND of invocation. Without the dedupe the
  // flag multiset differs per file and every compile becomes its own fold.
  const flags = [...new Set(rest.filter((a) => a.startsWith("-")).map(flagName))].sort();
  const verb = VERBED.test(e.comm) && rest.length && isVerb(rest[0]) ? " " + rest[0] : "";
  return e.comm + verb + (flags.length ? " " + flags.join(" ") : "");
};

// Human-readable form of the fold: the command with paths elided.
export const foldLabel = (e) => {
  const rest = e.argv.slice(1);
  if (isShellC(e.comm, rest)) {
    const f = shScriptFold(rest[rest.indexOf("-c") + 1] ?? "");
    return f === "#comment" ? `${e.comm} -c ⟨comment⟩` : `${e.comm} -c ${f} …`;
  }
  const out = [e.comm];
  let elided = 0;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("-")) out.push(a);
    else if (i === 0 && VERBED.test(e.comm) && isVerb(a)) out.push(a);
    else elided++;
  }
  if (elided) out.push(`⟨${elided} arg${elided > 1 ? "s" : ""}⟩`);
  return out.join(" ");
};

// What counts as sensitive: a command that touched a credential path, or one
// that reaches the network. The sandbox verdict is about WHETHER a command did
// one of these while in or out of the sandbox.
const SENSITIVE = [
  { id: "creds", label: "credential paths",
    test: (full) => /(\/\.ssh\b|\/\.aws\b|\/\.netrc\b|\/\.docker\/config|id_rsa|id_ed25519|\.pem\b|credentials)/.test(full) },
  { id: "net", label: "the network",
    test: (full, comm) => /^(curl|wget|nc|ncat|ssh|scp|sftp|rsync)$/.test(comm) || /\b(curl|wget)\b/.test(full) },
];

// Filesystem magic numbers. A credential file read for real lives on a normal
// disk filesystem; the sandbox's stand-in is a tmpfs directory mounted over the
// path, or /dev/null (devtmpfs) over a file. So the magic of the opened inode's
// filesystem is the kernel's own answer to "real file or stand-in".
const FS_STANDIN = new Set([
  0x1021994, // tmpfs; the empty dir the sandbox mounts over ~/.ssh
  0x1cd1,    // devpts
]);
const DEVTMPFS_NAMES = /^(null|zero|full)$/; // /dev/null stand-in over a file
// Credential-shaped leaf or directory names, matched on the open's path
// components rather than argv text; this is the file that was actually opened.
const CRED_PATH = /^(\.ssh|\.aws|\.netrc|id_rsa|id_ed25519|credentials|config)$|\.pem$/;

export function createModel(opts = {}) {
  // A thunk returning the watched agent's net namespace inode, or 0 if unknown.
  // When 0, the sandbox dimension stays off: no verdict, just the exec feed.
  const hostNetns = opts.hostNetns ?? (() => 0);
  const folds = new Map();   // key -> {key,label,comm,count,firstTs,lastTs,lats[],parents:Set,samples[],netnses:Set}
  // Per-pid credential-open outcomes, the join target for exec folds: a command
  // and its file opens share a pid. { reached: bool, path }.
  const credOpens = new Map();
  const parentComm = new Map(); // pid -> comm, so we can name a child's parent
  let total = 0;
  let t0 = Date.now();

  // The traced root is the agent process itself (claude, codex, ...), seeded at
  // attach. Its own exec carries the user's prompt as argv, so when the prompt
  // mentions a credential path the launcher reads as "reaching" one. That is the
  // prompt text, not a command the agent ran, and the agent runs in the host
  // namespace by nature, so without this it shows as a phantom "got past" on an
  // otherwise held run. We remember the root pid and never judge its own fold.
  const rootPids = new Set();
  const seed = (pid, comm) => { parentComm.set(pid, comm); rootPids.add(pid); };

  // A file-open event (lib/argv.normalizeOpen). We only use opens for ONE claim
  // we can actually stand behind: a credential file that was read FOR REAL,
  // outside the sandbox. That requires the open's OWN path to be
  // credential-shaped (so a later libc open from the same pid can't hijack the
  // path) and to sit on a real disk filesystem. The blocked/stand-in side is not
  // trusted here; a bwrap stand-in is a per-namespace mount the hook can't see -
  // so we record only the reached case and the file it reached.
  const addOpen = (o) => {
    const comps = o.comps ?? [];
    if (!comps.some((c) => CRED_PATH.test(c))) return; // its own path must be credential-shaped
    const leaf = comps[0] ?? "";
    const onStandinFs = FS_STANDIN.has(o.magic) || DEVTMPFS_NAMES.test(leaf);
    if (onStandinFs) return; // not a real read; and not a trustworthy block signal
    // Components come leaf-first and can include the mount root "/" one or more
    // times; reverse to root-first and collapse the leading slashes into one.
    const path = "/" + comps.slice().reverse().filter((c) => c && c !== "/").join("/");
    const prev = credOpens.get(o.pid) ?? { reached: false, path: "" };
    prev.reached = true;
    if (!prev.path) prev.path = path;
    credOpens.set(o.pid, prev);
  };

  const add = (e) => {
    total++;
    parentComm.set(e.pid, e.comm);
    const key = foldKey(e);
    let f = folds.get(key);
    if (!f) {
      f = { key, label: foldLabel(e), comm: e.comm, count: 0, firstTs: e.ts,
            lastTs: e.ts, lats: [], parents: new Set(), samples: [], netnses: new Set() };
      folds.set(key, f);
    }
    f.count++;
    f.lastTs = e.ts;
    f.lats.push(e.forkToExecUs);
    f.parents.add(parentComm.get(e.ppid) ?? "?");
    // Each distinct net namespace this fold ran in. One fold can straddle the
    // boundary; the escape run ran `ls ~/.ssh` once sandboxed and once not -
    // so the verdict pass walks per-sample namespaces, not a single fold flag.
    if (typeof e.netns === "number" && e.netns) f.netnses.add(e.netns);
    // Stamp wall-clock arrival. e.ts is the kernel's boot-relative ktime, so it
    // cannot be compared to Date.now() for an age. The verdict "age" column
    // reads wallTs instead.
    if (f.samples.length < 40) f.samples.push({ ...e, wallTs: Date.now() });
  };

  // ── sandbox verdicts ────────────────────────────────────────────────────────
  //
  // The whole point of a sandbox is that sensitive work done inside it is
  // declawed and the same work done outside it is not. So the verdict pairs two
  // kernel-observed facts about one exec: which net namespace it ran in (host =
  // alongside the agent, other = inside bwrap's unshared namespace), and whether
  // its command references something sensitive (a credential path, the network).
  //
  // Wording is deliberately narrow, per the credibility rule: the kernel tells
  // us an exec ran in the host namespace, NOT that it "escaped"; an approved
  // retry, a command the sandbox excludes, and a command you ran yourself all
  // look identical here. So a host-namespace sensitive exec reads "ran outside
  // the sandbox", and the detail names what the command reached, from argv, not
  // a claim about the open's result (that is the file-open probe's job).
  //
  // sandboxDetected(): true once we know the agent's namespace AND have seen at
  // least one exec in a different one. Until then there is no sandbox to judge.
  const sandboxDetected = () => {
    const host = hostNetns();
    if (!host) return false;
    for (const f of folds.values())
      for (const ns of f.netnses) if (ns !== host) return true;
    return false;
  };

  // A launcher carries the command it will run as its own argv tail: `bwrap …
  // ls ~/.ssh`, `unshare -rn sh -c 'ls ~/.ssh'`, `sudo ls ~/.ssh`. Scanning its
  // full argv would attribute the child's sensitivity to the launcher, which
  // then reads as the sandbox-maker itself reaching credentials; the opposite
  // of true. The child's own exec is what we judge, so a launcher contributes
  // no verdict of its own. mount/umount set up or tear down the stand-in itself,
  // so they are not a credential finding either.
  const LAUNCHER = /^(unshare|bwrap|nsenter|sudo|doas|env|setsid|chroot|runuser|setpriv|timeout|stdbuf|nice|ionice|firejail|mount|umount)$/;

  // The agent binary itself. When it launches it carries the user's prompt as
  // argv (`claude -p "...check ~/.ssh..."`), so the prompt's own mention of a
  // credential path makes the launcher read as reaching one, and it runs in the
  // host namespace by nature. That is the agent, not a command it ran, so it
  // gets no verdict. A tool call the agent spawns is a child process running a
  // real command (cat, ssh, ls), which is judged normally.
  const AGENT = /^(claude|codex|aider|cursor|cursor-agent|goose|cline|opencode)$/;

  const sensitiveReasons = (f) => {
    if (LAUNCHER.test(f.comm)) return [];
    // The agent process itself, by name or as the seeded root. Matching the
    // name covers the real tree, where `claude -p` is a child of the launch
    // wrapper and so does not carry the seeded root pid.
    if (AGENT.test(f.comm)) return [];
    if (f.samples.length && f.samples.every((s) => rootPids.has(s.pid))) return [];
    // A shell whose script is itself just a launcher/mount (`sh -c 'mount …'`,
    // `sh -c 'unshare …'`) is setting the sandbox up, not reading a secret -
    // the fold label carries the leading command, so key off that.
    if (/^(sh|bash|dash|zsh) -c /.test(f.label) && LAUNCHER.test(f.label.replace(/^\S+ -c /, "").split(/\s/)[0] ?? ""))
      return [];
    const full = f.samples.map((s) => s.argv.join(" ")).join(" \n");
    return SENSITIVE.filter((s) => s.test(full, f.comm)).map((s) => s.label);
  };

  // One finding per (fold, side of the boundary) that did something sensitive.
  // A fold that ran a sensitive command both inside and outside the sandbox
  // yields two findings; that split is exactly the story worth telling.
  const verdicts = () => {
    const host = hostNetns();
    if (!host) return { detected: false, past: [], blocked: [] };
    const past = [];
    const blocked = [];
    for (const f of folds.values()) {
      const labels = sensitiveReasons(f);
      if (!labels.length) continue;
      const reach = labels.join(" and ");
      // Partition this fold's samples by which side of the boundary they ran on.
      // Only the host side uses file-open evidence, and only to confirm a real
      // read: if one of these pids opened a credential file on a real filesystem,
      // "its command reaches X" (argv inference) becomes "opened your real X" (a
      // kernel fact). The sandbox side has no trustworthy open signal.
      let outN = 0;
      let inN = 0;
      let lastOut = 0;
      let lastIn = 0;
      let outReached = false;
      let reachedPath = "";
      for (const s of f.samples) {
        if (!s.netns) continue;
        if (s.netns === host) {
          outN++; lastOut = Math.max(lastOut, s.wallTs);
          const ev = credOpens.get(s.pid);
          if (ev?.reached) { outReached = true; if (ev.path) reachedPath = ev.path; }
        } else {
          inN++; lastIn = Math.max(lastIn, s.wallTs);
        }
      }
      const named = reachedPath || reach;
      if (outN) {
        // Outside the sandbox, a reached real file is the strong statement; fall
        // back to the argv inference when we have no open evidence for it.
        const detail = outReached
          ? `ran outside the sandbox · opened your real ${named}`
          : `ran outside the sandbox · its command reaches ${reach}`;
        past.push({ fold: f, ts: lastOut, reach, verified: outReached, detail });
      }
      if (inN) {
        // The blocked side is NOT kernel-verified. A bwrap stand-in is a
        // per-namespace mount, and security_file_open resolves the inode against
        // the host mount namespace; so the superblock magic of a sandboxed open
        // reads as the real filesystem even when the stand-in genuinely hid the
        // file (measured against real bwrap). A missing file in the stand-in also
        // fails before the hook fires, so there is often no open at all. The
        // truth we DO have is the namespace: this command ran inside the sandbox,
        // where that credential path is walled off. We state exactly that and
        // claim nothing about the open we cannot see.
        blocked.push({
          fold: f, ts: lastIn, reach, verified: false,
          detail: `ran inside the sandbox · ${reach} walled off`,
        });
      }
    }
    // Drop a shell-wrapper finding when the command it runs is itself a finding
    // on the same side. `sh -c 'cat ~/.ssh/key'` and the `cat` it spawns are one
    // action seen twice; the child carries the real comm and the open evidence,
    // so it is the one to keep. We only fold away the wrapper, never a bare shell
    // that is itself the sensitive thing.
    const dedupeShells = (list) => {
      const childCmds = new Set(
        list.filter((v) => !/^(sh|bash|dash|zsh) -c /.test(v.fold.label)).map((v) => v.fold.comm),
      );
      return list.filter((v) => {
        const m = /^(sh|bash|dash|zsh) -c (\S+)/.exec(v.fold.label);
        if (!m) return true;                 // not a wrapper
        return !childCmds.has(m[2]);         // keep only if its child isn't already shown
      });
    };

    // Most recent first: a live watcher cares about what just happened.
    const p = dedupeShells(past).sort((a, b) => b.ts - a.ts);
    const b = dedupeShells(blocked).sort((a, b) => b.ts - a.ts);
    return { detected: sandboxDetected(), past: p, blocked: b };
  };

  // Every sensitive command sandbox-watch saw, folded; the ATTEMPTS,
  // independent of where they ran. The outcome panels say what the sandbox did
  // with them; this says what the agent tried, so both read at once. Same
  // sensitivity test as the verdicts, so a row here always corresponds to a
  // got-past or blocked row.
  const attempts = () => {
    const out = [];
    for (const f of folds.values()) {
      const labels = sensitiveReasons(f);
      if (!labels.length) continue;
      out.push({ fold: f, count: f.count, reach: labels.join(" and "), lastTs: f.lastTs });
    }
    // Most-recent first, like the panels above it.
    return out.sort((a, b) => b.lastTs - a.lastTs);
  };

  return {
    add, addOpen, seed,
    get total() { return total; },
    get elapsed() { return (Date.now() - t0) / 1000; },
    // The full exec feed: every command the agent launched, folded, most-run
    // first. The verdict panels show the sensitive commands and what the sandbox
    // did with them; this is the complete context underneath.
    folds: () => [...folds.values()].sort((a, b) => b.count - a.count),
    verdicts, attempts, sandboxDetected,
  };
}
