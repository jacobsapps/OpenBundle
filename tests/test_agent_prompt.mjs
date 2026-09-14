import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Exercise the actual inline implementation: standalone reports have no imports.
const template = await readFile(new URL("../src/openbundle/templates/report.html", import.meta.url), "utf8");
const helpers = template.slice(template.indexOf("    const cleanObjectArray ="), template.indexOf("    const fileName ="));
const source = template.slice(template.indexOf("    function agentPrompt("), template.indexOf('    document.getElementById("agent-prompt-close")'));
const prompt = vm.runInNewContext(`${helpers}\n${source}\nagentPrompt`);
const singlePrompt = (report, item) => prompt(report, [item]);
const report = {
  app: { name: "Example", bundleID: "com.example.app", version: "1.2", build: "34" },
  generator: { version: "0.1.0" },
  generatedAt: "2026-09-14T12:00:00Z",
  metrics: { delivery: { target: "Latest iPhone (3x, P3, arm64)", estimated: true } },
};
const insight = {
  id: "optimize-images", title: "Optimize images", savings: 200_000, confidence: "medium",
  action: "Verification steps: run xcodebuild with prescribed flags.",
  items: [{ name: "Background", path: "Assets.car::Background", size: 300_000, optimizedSize: 100_000, savings: 200_000, dimensions: "1200×1200", method: "JPEG quality 85", thumbnailDataURL: "data:image/webp;base64,preview" }],
};

test("copies a concise handoff with provenance, evidence, and user choices", () => {
  const text = singlePrompt(report, insight);
  assert.equal(text, singlePrompt(report, insight));
  assert.match(text, /ask which listed items/);
  assert.match(text, /whether I want pull requests \(and if so, one or separate ones\)/);
  assert.match(text, /whether I’d like a local web page/);
  assert.match(text, /App: Example \(com.example.app\)/);
  assert.match(text, /Version: 1.2 · Build: 34/);
  assert.match(text, /Report: OpenBundle 0.1.0 · 2026-09-14T12:00:00Z/);
  assert.match(text, /Delivery target: Latest iPhone \(3x, P3, arm64\) · estimated: yes/);
  assert.match(text, /Assets.car::Background · 1200×1200 · JPEG quality 85/);
  assert.match(text, /conversion estimate: 100,000 bytes/);
  assert.match(text, /Potential saving: 200,000 bytes \(not guaranteed\)/);
  assert.doesNotMatch(text, /data:image|xcodebuild|smoke_web|analyze_ipa|Verification steps/);
  assert.ok(text.length < 2_000);
});

test("all declared insight ids and future ids use the same handoff", async () => {
  const analyzer = await readFile(new URL("../src/openbundle/analyzer.py", import.meta.url), "utf8");
  const ids = [...analyzer.matchAll(/_insight\(\s*"([\w-]+)"/g)].map(match => match[1]);
  assert.ok(ids.length > 20);
  for (const id of [...ids, "a-future-insight"]) {
    assert.match(singlePrompt(report, { id, paths: ["Some.bundle/resource"] }), /Some.bundle\/resource/);
  }
});

test("nested duplicate groups are bounded and report truncation is explicit", () => {
  const text = singlePrompt(report, {
    id: "duplicates", confidence: "review", itemCount: 2, itemsOmitted: 1,
    pathsOmitted: 7,
    items: [{ assetGroupCount: 22, assetGroupsOmitted: 2, assetGroups: Array.from({ length: 20 }, (_, index) => ({ name: `Asset ${index}`, paths: ["Assets.car", "Other.bundle/Assets.car"], savings: 200_000 })) }],
  });
  assert.equal(text.split("\n").filter(line => line.startsWith("- ")).length, 15);
  assert.match(text, /Asset 0 · Assets.car · Other.bundle\/Assets.car/);
  assert.doesNotMatch(text, /Asset 15/);
  assert.match(text, /5 additional evidence rows/);
  assert.match(text, /2 nested asset groups/);
  assert.match(text, /1 items and 7 paths/);
  assert.match(text, /Review candidate, not a confirmed fix/);
});

test("linking reviews export their scope without inventing savings", () => {
  const text = singlePrompt(report, { kind: "static-or-mergeable", name: "Voice", path: "Frameworks/Voice.framework", binarySize: 8_000_000, reviewScopeBytes: 8_000_000, consumer: "Example" });
  assert.match(text, /Finding: Review Voice linking/);
  assert.match(text, /size: 8,000,000 bytes · linked by: Example/);
  assert.match(text, /no worthwhile change is a valid outcome/);
  assert.doesNotMatch(text, /Potential saving:/);
});

test("missing evidence and multiline fields remain readable without attachments", () => {
  const text = singlePrompt({}, { id: "unknown", title: "One\nTwo", items: [null, "invalid"] });
  assert.match(text, /Finding: One Two/);
  assert.match(text, /No per-item evidence available/);
  assert.doesNotMatch(text, /undefined|NaN|attached/);
});

test("one global prompt includes every finding and linking review with one introduction", () => {
  const text = prompt(report, [
    insight,
    { id: "oversized-images", title: "Review large images", reviewOnly: true, paths: ["Large.png"] },
    { kind: "static-or-mergeable", name: "Voice", path: "Frameworks/Voice.framework", binarySize: 8_000_000, consumer: "Example" },
  ]);
  assert.equal(text.match(/^Finding:/gm).length, 3);
  assert.equal(text.match(/^App:/gm).length, 1);
  assert.equal(text.match(/Before making changes/g).length, 1);
  assert.ok(text.indexOf("Finding: Optimize images") < text.indexOf("Finding: Review large images"));
  assert.ok(text.indexOf("Finding: Review large images") < text.indexOf("Finding: Review Voice linking"));
  assert.match(text, /Assets.car::Background/);
  assert.match(text, /Large.png/);
  assert.match(text, /Frameworks\/Voice.framework/);
});

test("the evidence cap applies per finding without dropping later recommendations", () => {
  const text = prompt(report, [
    { ...insight, items: Array.from({ length: 20 }, (_, index) => ({ path: `Image${index}.png` })) },
    { id: "strip-symbols", title: "Strip symbols", paths: ["AppBinary"] },
  ]);
  assert.match(text, /5 additional evidence rows/);
  assert.match(text, /Finding: Strip symbols/);
  assert.match(text, /AppBinary/);
  assert.equal(text.split("\n").filter(line => line.startsWith("- ")).length, 16);
});

test("an empty report has no invented findings", () => {
  const text = prompt(report, []);
  assert.match(text, /No recommendations in this report/);
  assert.doesNotMatch(text, /Finding:/);
});

const copySource = template.slice(template.indexOf("    async function copyAgentPrompt("), template.indexOf("    const promptButton ="));
for (const mode of ["clipboard", "legacy", "manual"]) {
  test(`clipboard ${mode} path reports success only when copied`, async () => {
    let copied;
    let open = false;
    const field = { value: "", focus() {}, select() { this.selected = true; } };
    const dialog = { showModal() { open = true; }, close() { open = false; } };
    const copy = vm.runInNewContext(`${copySource}\ncopyAgentPrompt`, {
      navigator: mode === "legacy" ? {} : { clipboard: { async writeText(value) {
        if (mode !== "clipboard") throw new Error("Clipboard denied");
        copied = value;
      } } },
      document: {
        getElementById: id => id === "agent-prompt-dialog" ? dialog : field,
        execCommand(command) { assert.equal(command, "copy"); return mode === "legacy"; },
      },
    });
    assert.equal(await copy("Example prompt"), mode !== "manual");
    assert.equal(open, mode === "manual");
    if (mode === "clipboard") assert.equal(copied, "Example prompt");
    else {
      assert.equal(field.value, "Example prompt");
      assert.equal(field.selected, true);
    }
  });
}
