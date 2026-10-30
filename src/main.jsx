/* sandbox-watch; did the agent's sandbox hold, watched from the kernel.
 *
 * It answers one question a transcript cannot: of the commands a sandboxed
 * agent ran, which ran INSIDE the sandbox (where a credential path or the
 * network was walled off) and which ran OUTSIDE it, in the agent's own
 * namespace. The signal is the net namespace: bwrap unshares it for a
 * sandboxed command, so a command whose namespace differs from the agent's ran
 * inside the sandbox, and one whose namespace matches ran outside it. A
 * file-open probe upgrades the outside case to a kernel fact when a credential
 * read landed on the real file.
 *
 *   kernel → user : probes/probe.js loads the object; probes/watch.js seeds the
 *                   traced set, subscribes to the exec + open ring buffers, and
 *                   feeds the pure aggregation in lib/model.js.
 *
 * Layout: probes/ (BPF-aware) → components/ (pure UI) → lib/ (pure helpers),
 * composed here. One screen: the verdict, then the full exec feed underneath.
 */
import { Box, Text, computed, mount, signal } from "yeet:tui";
import {
  flashes, folds, paused, seedExisting, seedRoot, setPaused, status, tick, verdicts,
} from "@/probes/watch.js";
import { commOf, containerRoot, descendantsOf, listContainers, procTable } from "@/lib/scope.js";
import TitleBar from "@/components/titlebar.jsx";
import Sandbox, { verdictList } from "@/components/sandbox.jsx";
import Footer from "@/components/footer.jsx";

// ── scope ────────────────────────────────────────────────────────────────────
const scope = signal("resolving…");
const args = yeet.args ?? {};

async function resolveScope() {
  const container = args.container ?? args.c;
  const pid = Number(args.pid ?? args.p ?? 0);

  if (container) {
    let c;
    try {
      c = await containerRoot(container);
    } catch (err) {
      // A wrong container name is the most likely mistake here, so say what
      // IS running rather than just failing.
      const names = (await listContainers()).filter((x) => x.state === "RUNNING").map((x) => x.name);
      throw new Error(
        `${err.message}${names.length ? `\n  running: ${names.join(", ")}` : ""}`,
      );
    }
    await seedRoot(c.pid, c.comm);
    const existing = await seedExisting(descendantsOf(await procTable(), c.pid));
    scope.set(`container ${c.label}`);
    status.set(`agent subtree · ${existing} existing process${existing === 1 ? "" : "es"} seeded`);
    return;
  }
  if (pid) {
    await seedRoot(pid, await commOf(pid));
    if (args.launched) {
      // bin/sandbox-watch parked the agent with SIGSTOP before it exec'd, so the
      // probe attached before it ran anything: the tree really is complete, and
      // the sandbox setup itself is captured from its first fork.
      scope.set(`launched pid ${pid}`);
      status.set("complete tree · the agent was parked until the probe attached");
    } else {
      scope.set(`pid ${pid}`);
      const existing = await seedExisting(descendantsOf(await procTable(), pid));
      status.set(`agent subtree · ${existing} existing child${existing === 1 ? "" : "ren"} seeded`);
    }
    return;
  }
  // No scope given: watching a sandbox needs a single agent to compare against,
  // so there is nothing useful to do unscoped. Say so rather than seeding the
  // whole host and showing a verdict that can never turn on.
  await seedRoot(1, "systemd");
  const n = await seedExisting(
    (await procTable()).filter((s) => s.pid !== 1).map((s) => ({ ...s, depth: 0 })),
  );
  scope.set("whole host");
  status.set(`unscoped · ${n} processes seeded; pass --pid or launch with -- to judge one agent`);
}

await resolveScope();

// ── cursor over the verdict list ──────────────────────────────────────────────
const sbxSel = signal(0);
const focus = signal("sandbox");
const sbxFocused = computed(() => focus.get() === "sandbox");

const move = (d) => {
  const n = verdictList(verdicts()).length;
  sbxSel.set(Math.max(0, Math.min(Math.max(0, n - 1), sbxSel.get() + d)));
};

// How many feed rows fit below the verdict. The feed sits under the two verdict
// panels, so it gets whatever the viewport has left. Reads the reactive size
// signal, not tty.size(), so it agrees with the layout the tree is laid out for.
const CHROME = 2;      // title rail + footer rail
const HEADER = 3;      // headline + explainer + blank
const feedBudgetFor = (rows) => {
  const v = verdicts();
  const findingLines = v.detected
    ? 2 + Math.max(1, v.past.length) + 1 + Math.max(1, v.blocked.length) // two rules + rows + blank
    : 2; // the "no sandbox / waiting" line + blank
  const feedChrome = 2; // blank + the feed rule
  return Math.max(3, rows - CHROME - HEADER - findingLines - feedChrome - 1);
};

// ── input ────────────────────────────────────────────────────────────────────
tty.enableMouse();

tty.on("keydown", (e) => {
  const code = e.code;
  const k = (e.key ?? "").toLowerCase();
  if (code === "Escape" || k === "q") return yeet.exit();
  if (k === "p") return setPaused(!paused.get());
  if (code === "ArrowDown" || k === "j") return move(1);
  if (code === "ArrowUp" || k === "k") return move(-1);
  if (code === "PageDown") return move(10);
  if (code === "PageUp") return move(-10);
  if (k === "g") return sbxSel.set(0);
});

tty.on("wheel", (e) => move(e.deltaY > 0 ? 3 : -3));

// ── layout ───────────────────────────────────────────────────────────────────
const Root = (size) => {
  // `width` is a THUNK, never a snapshot. Passing size.get().cols as a plain
  // value reads the signal during view construction, which freezes that whole
  // subtree for the life of the process.
  const width = () => size.get().cols;
  return (
    <Box>
      <TitleBar scope={scope} status={status} paused={paused} />
      <Box height="1fr" overflow="hidden">
        <Sandbox
          tick={tick} verdicts={verdicts} folds={folds} flashes={flashes}
          selected={sbxSel} focused={sbxFocused} width={width}
          feedRows={() => feedBudgetFor(size.get().rows)}
        />
      </Box>
      <Footer paused={paused} />
    </Box>
  );
};

mount(Root);
await new Promise(() => {}); // keep the script alive; the TUI owns the screen
