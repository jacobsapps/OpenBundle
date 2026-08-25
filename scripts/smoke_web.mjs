#!/usr/bin/env node
/* Smoke-test the built browser host with a real archive and local Chrome. */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const chromePath =
  process.env.CHROME_PATH ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const siteURL = process.argv[2] || "http://127.0.0.1:8000/";
const artifactPath = process.argv[3] ? resolve(process.argv[3]) : null;

if (!artifactPath) {
  throw new Error("Usage: node scripts/smoke_web.mjs <site-url> <artifact.ipa>");
}

const delay = (milliseconds) =>
  new Promise((resolveValue) => setTimeout(resolveValue, milliseconds));

const port = 12000 + Math.floor(Math.random() * 10000);
const profile = mkdtempSync(join(tmpdir(), "openbundle-chrome-"));
const windowSize = process.env.WINDOW_SIZE || "1440,1200";
const chrome = spawn(
  chromePath,
  [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--window-size=${windowSize}`,
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`,
    "about:blank",
  ],
  { stdio: "ignore" },
);

let socket;
let nextID = 1;
const pending = new Map();

function command(method, params = {}) {
  const id = nextID++;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolveValue, reject) => {
    pending.set(id, { resolve: resolveValue, reject });
  });
}

async function connect() {
  let targets;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      break;
    } catch {
      await delay(100);
    }
  }
  const page = targets?.find((target) => target.type === "page");
  if (!page) throw new Error("Chrome DevTools target did not start.");

  socket = new WebSocket(page.webSocketDebuggerUrl);
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Page.javascriptDialogOpening") {
      void command("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
      return;
    }
    if (!message.id || !pending.has(message.id)) return;
    const handler = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) handler.reject(new Error(message.error.message));
    else handler.resolve(message.result);
  });
  await new Promise((resolveValue, reject) => {
    socket.addEventListener("open", resolveValue, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
}

try {
  await connect();
  await command("Page.enable");
  await command("DOM.enable");
  await command("Runtime.enable");
  if (process.env.REDUCED_MOTION === "1") {
    await command("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-reduced-motion", value: "reduce" }],
    });
  }
  await command("Page.navigate", { url: siteURL });

  let inputReady = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = await command("Runtime.evaluate", {
      expression:
        'Boolean(document.querySelector("#artifact-input") && document.documentElement.dataset.openbundleReady === "true")',
      returnByValue: true,
    });
    if (response.result.value) {
      inputReady = true;
      break;
    }
    await delay(100);
  }
  if (!inputReady) throw new Error("Browser host did not render its file input.");

  const documentNode = await command("DOM.getDocument");
  const inputNode = await command("DOM.querySelector", {
    nodeId: documentNode.root.nodeId,
    selector: "#artifact-input",
  });
  await command("DOM.setFileInputFiles", {
    nodeId: inputNode.nodeId,
    files: [artifactPath],
  });

  let state;
  // Large production IPAs can contain tens of thousands of catalog renditions.
  // Give the real browser worker up to ten minutes while still failing quickly
  // when the UI reports an error.
  for (let attempt = 0; attempt < 1200; attempt += 1) {
    const response = await command("Runtime.evaluate", {
      expression: `JSON.stringify({
        complete: !document.querySelector("#result").hidden,
        error: document.querySelector("#status").classList.contains("is-error"),
        status: document.querySelector("#status-text").textContent,
        reportLength: document.querySelector("#report-frame").srcdoc.length
      })`,
      returnByValue: true,
    });
    state = JSON.parse(response.result.value);
    if (state.complete || state.error) break;
    await delay(500);
  }

  if (!state?.complete || state.error || state.reportLength < 50000) {
    throw new Error(`Browser analysis failed: ${state?.status || "timed out"}`);
  }
  const response = await command("Runtime.evaluate", {
    expression: `JSON.stringify({
      html: document.querySelector("#report-frame").srcdoc,
      json: (() => {
        const html = document.querySelector("#report-frame").srcdoc;
        const report = new DOMParser().parseFromString(html, "text/html");
        return report.querySelector("#report-data")?.textContent || "";
      })()
    })`,
    returnByValue: true,
  });
  const exported = JSON.parse(response.result.value);
  const analysis = JSON.parse(exported.json);
  if (analysis.capabilities?.environment !== "browser") {
    throw new Error("Smoke report did not use the browser platform.");
  }
  const coverage = analysis.capabilities?.assetCatalogCoverage || {};
  if (Number(coverage.parsedCatalogCount || 0) !== Number(coverage.catalogCount || 0)) {
    throw new Error(
      `Asset-catalog smoke failure: parsed ${coverage.parsedCatalogCount || 0}/${coverage.catalogCount || 0}.`,
    );
  }
  const expectedInsights = (process.env.EXPECT_INSIGHT_IDS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const actualInsights = new Set(analysis.insights.map((item) => item.id));
  for (const insight of expectedInsights) {
    if (!actualInsights.has(insight)) {
      throw new Error(`Expected browser insight was missing: ${insight}`);
    }
  }

  if (process.env.HOST_SCREENSHOT_PATH) {
    await delay(500);
    const hostScreenshot = await command("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
    });
    writeFileSync(
      resolve(process.env.HOST_SCREENSHOT_PATH),
      hostScreenshot.data,
      "base64",
    );
  }

  // A sandboxed srcdoc has an opaque origin, so the host page cannot inspect
  // its DOM. Navigate the same isolated browser tab to a Blob URL built from
  // the generated HTML and validate the downloadable report itself.
  await command("Runtime.evaluate", {
    expression: `location.href = URL.createObjectURL(new Blob([
      document.querySelector("#report-frame").srcdoc
    ], { type: "text/html" }))`,
  });

  let reportUI;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const rendered = await command("Runtime.evaluate", {
        expression: `(() => {
          const recommendationCards = [...document.querySelectorAll("#recommendations-list .recommendation")];
          const recommendations = recommendationCards.filter((element) => element.hasAttribute("data-insight-id"));
          const linkingReviewCards = recommendationCards.filter((element) => element.hasAttribute("data-linking-review"));
          const recommendationSavings = recommendations.map((element) => Number(element.dataset.savings));
          const reportData = JSON.parse(document.querySelector("#report-data").textContent);
          const qualifyingRecommendations = reportData.insights.filter((item) => typeof item.savings === "number" && Number.isFinite(item.savings) && item.savings >= 100000);
          const linkingReviews = (reportData.architecture?.linkingReviews || []).filter((item) => Number.isFinite(Number(item.reviewScopeBytes)) && Number(item.reviewScopeBytes) > 0).sort((a,b) => Number(b.reviewScopeBytes) - Number(a.reviewScopeBytes)).slice(0,3);
          const duplicateGroup = (item) => String(item?.group || item?.duplicateGroup || item?.duplicateCatalogGroup || item?.metadata?.duplicateCatalogGroup || "");
          const treeHasDuplicateEvidence = (node) => Boolean(
            duplicateGroup(node)
            || Number(node?.metadata?.duplicateCount || 0) > 0
            || (node?.children || []).some(treeHasDuplicateEvidence)
          );
          const duplicateInsight = qualifyingRecommendations.find((item) => item.id === "duplicates");
          const duplicateRecommendation = recommendations.find((element) => element.dataset.insightId === "duplicates");
          const duplicateEvidenceRows = [...(duplicateRecommendation?.querySelectorAll(".recommendation-evidence") || [])];
          const allowedDuplicateTypes = new Set(["file","catalog","component","asset"]);
          const duplicateEvidenceSemantics = !duplicateInsight || (duplicateEvidenceRows.length === (duplicateInsight.items || []).length
            && (duplicateInsight.items || []).every((item,index) => {
              const row = duplicateEvidenceRows[index];
              const sourceGroup = duplicateGroup(item);
              const isCatalog = row?.dataset.duplicateType === "catalog";
              const catalogHasDetails = !isCatalog
                || (!Number(item.repeatedAssetCount || 0) && !(item.assetGroups || []).length)
                || Boolean(row.querySelector(".duplicate-catalog-summary"));
              return allowedDuplicateTypes.has(row?.dataset.duplicateType)
                && Boolean(row.querySelector(".duplicate-type-badge"))
                && Boolean(row.querySelector(".duplicate-actionability"))
                && (!sourceGroup || row.dataset.duplicateGroup === sourceGroup)
                && catalogHasDetails;
            }));
          const recommendationsNav = document.querySelector('[data-view="insights"]');
          const recommendationsCount = document.querySelector("#recommendations-count")?.textContent || "";
          const capabilityDeclarations = reportData.capabilities?.declarations || {};
          const declaredCapabilityTargets = (capabilityDeclarations.targets || []).filter((target) => Boolean(target.extensionPoint)
            || ["permissions","backgroundModes","backgroundTasks","urlSchemes","queriedSchemes","bonjourServices","transportDomains","requiredDeviceCapabilities","entitlements"]
              .some((key) => Array.isArray(target[key]) && target[key].length));
          const hasCapabilities = declaredCapabilityTargets.length > 0 || (capabilityDeclarations.privacyManifests || []).length > 0;
          const hasLocales = (reportData.locales?.rows || []).length > 0;
          const binaryItems = reportData.binaries?.items || [];
          const binaryRows = [...document.querySelectorAll("#binaries-stack .binary-item")];
          const treeContainsDuplicates = treeHasDuplicateEvidence(reportData.tree);
          const duplicateKey = document.querySelector("#duplicate-map-key");
          const renderedDuplicationNodes = [...document.querySelectorAll("#bundle-map .treemap-block.duplication[data-duplicate-group], #bundle-map .treemap-group-label.duplication[data-duplicate-group]")];
          document.querySelector('#image-sources [data-source="all-images"]')?.click();
          for (let page = 0; page < 50 && document.querySelector("#show-more-images"); page += 1) document.querySelector("#show-more-images").click();
          const imageDuplicateRows = [...document.querySelectorAll("#image-list [data-duplicate-count]")];
          const architectureDuplicateRows = [...document.querySelectorAll("#architecture-stack .architecture-duplicate-item")];
          const blocks = [...document.querySelectorAll("#bundle-map .treemap-block")]
            .map((element) => element.getBoundingClientRect())
            .filter((rect) => rect.width > 0 && rect.height > 0);
          let overlappingTilePairs = 0;
          for (let left = 0; left < blocks.length; left += 1) {
            for (let right = left + 1; right < blocks.length; right += 1) {
              const width = Math.min(blocks[left].right,blocks[right].right) - Math.max(blocks[left].left,blocks[right].left);
              const height = Math.min(blocks[left].bottom,blocks[right].bottom) - Math.max(blocks[left].top,blocks[right].top);
              if (width * height > .25 && width > 0 && height > 0) overlappingTilePairs += 1;
            }
          }
          return JSON.stringify({
            recommendations: recommendations.length,
            recommendationsMatchData: recommendations.length === qualifyingRecommendations.length,
            linkingReviewsMatchData: linkingReviewCards.length === linkingReviews.length,
            linkingReviewMetricsAreScope: linkingReviewCards.every((element,index) => !element.hasAttribute("data-savings") && /binary/i.test(element.querySelector(".recommendation-saving")?.textContent || "") && Number(linkingReviews[index]?.reviewScopeBytes || 0) > 0),
            staleFrameworkReviewTags: [...document.querySelectorAll("#architecture-stack .architecture-tag")].filter((element) => /review static|mergeable/i.test(element.textContent || "")).length,
            recommendationsCountMatchesData: recommendationsCount === qualifyingRecommendations.length.toLocaleString(),
            recommendationsNavAccessible: recommendationsNav?.getAttribute("aria-label") === "Recommendations, " + qualifyingRecommendations.length.toLocaleString() + " available",
            recommendationsSorted: recommendationSavings.every((value,index) => index === 0 || recommendationSavings[index - 1] >= value),
            recommendationsMaterial: recommendationSavings.every((value) => Number.isFinite(value) && value >= 100000),
            recommendationIconsMissing: recommendationCards.filter((element) => !element.querySelector(".recommendation-icon svg")).length,
            recommendationExpanders: recommendationCards.filter((element) => element.matches("details")).length,
            expectedRecommendationExpanders: qualifyingRecommendations.filter((item) => Array.isArray(item.items) && item.items.length).length + linkingReviews.length,
            recommendationsAllExpandable: qualifyingRecommendations.every((item) => Array.isArray(item.items) && item.items.length),
            recommendationEvidenceMatches: qualifyingRecommendations.every((item,index) => {
              const expected = Array.isArray(item.items) ? item.items.length : 0;
              const actual = recommendations[index]?.querySelectorAll(".recommendation-evidence").length || 0;
              return actual === expected;
            }),
            duplicateEvidenceSemantics,
            hasPotentialBadges: [...document.querySelectorAll(".recommendation-saving span")].some((element) => /potential/i.test(element.textContent || "")),
            treemapTiles: document.querySelectorAll("#bundle-map .treemap-block, #bundle-map .treemap-group").length,
            overlappingTilePairs,
            treemapLayers: document.querySelectorAll("#bundle-map .treemap-layer").length,
            hasStaleMapRecommendationUI: Boolean(document.querySelector("#map-key, .map-recommendation-mark, #bundle-map .has-recommendation")),
            duplicateKeyMatchesData: Boolean(duplicateKey) && duplicateKey.hidden === !treeContainsDuplicates,
            duplicateKeyIsUnified: duplicateKey?.querySelectorAll(".duplicate-key-row").length === 1 && duplicateKey?.textContent.trim() === "Duplication",
            duplicationNodesAccessible: renderedDuplicationNodes.every((element) => /duplication/i.test(element.getAttribute("aria-label") || "")),
            duplicateTaxonomyRemoved: !document.querySelector("#duplicate-key-repeated, .exact-duplicate, .repeated-assets, .contains-duplicates, .duplicate-group-badge"),
            imageDuplicateSummariesValid: imageDuplicateRows.every((element) => Boolean(element.querySelector(".image-exact-match")) && /duplication/i.test(element.querySelector(".image-row")?.getAttribute("aria-label") || element.getAttribute("aria-label") || "")),
            architectureDuplicateSemantics: architectureDuplicateRows.every((element) => allowedDuplicateTypes.has(element.dataset.duplicateType) && ["review-every-runtime","review-target-membership"].includes(element.dataset.duplicateActionability) && Boolean(element.querySelector(".duplicate-type-badge")) && Boolean(element.querySelector(".duplicate-actionability")) && /duplication/i.test(element.querySelector(":scope > summary")?.getAttribute("aria-label") || "")),
            architectureDuplicateCopyClear: !architectureDuplicateRows.length || [...document.querySelectorAll("#architecture-stack .architecture-header")].some((element) => /repeated footprint/i.test(element.textContent || "")),
            bundleTreemapNavLabel: document.querySelector('[data-view="map"] > span:last-child')?.textContent.trim(),
            bundleTreemapHeader: document.querySelector("#view-map .view-head h2")?.textContent.trim(),
            undersizedDrillTargets: [...document.querySelectorAll("#bundle-map button.treemap-block, #bundle-map .treemap-group-label")]
              .filter((element) => { const rect = element.getBoundingClientRect(); return rect.width < 23.9 || rect.height < 23.9; }).length,
            nativeParentTitles: [...document.querySelectorAll("#bundle-map .treemap-group-label")].filter((element) => element.title).length,
            imageSources: document.querySelectorAll("#image-sources .image-source").length,
            binariesMatchData: binaryRows.length === binaryItems.length,
            binariesSorted: binaryItems.every((item,index) => index === 0 || Number(binaryItems[index - 1].size || 0) >= Number(item.size || 0)),
            binariesComplete: binaryItems.every((item) => Array.isArray(item.architectures) && (!item.parsed || item.architectures.length > 0) && typeof item.target === "string" && typeof item.owner === "string" && typeof item.encrypted === "boolean" && typeof item.stripSymbolsBytes === "number" && typeof item.exportedSymbolMetadataBytes === "number"),
            binaryOpportunityColumns: document.querySelectorAll(".binary-header [data-binary-sort=stripSymbolsBytes], .binary-header [data-binary-sort=exportedSymbolMetadataBytes]").length,
            blockingGroupFrames: [...document.querySelectorAll("#bundle-map .treemap-group")].filter((element) => getComputedStyle(element).pointerEvents !== "none").length,
            oversizedGroupHeaders: [...document.querySelectorAll("#bundle-map .treemap-group-label")].filter((element) => element.getBoundingClientRect().height > 34).length,
            reportNavCount: document.querySelectorAll(".side-nav [data-view]").length,
            visibleReportNavCount: [...document.querySelectorAll(".side-nav [data-view]")].filter((element) => !element.hidden && getComputedStyle(element).display !== "none").length,
            expectedVisibleReportNavCount: 5 + Number(hasCapabilities) + Number(hasLocales),
            metricLabels: [...document.querySelectorAll(".rail-metric > span")].map((element) => element.textContent.trim()),
            hasInventory: Boolean(document.querySelector('[data-view="inventory"], #view-inventory, #inventory-list')),
            hasFileBrowser: Boolean(document.querySelector('[data-view="files"], #view-files, #file-browser')),
            hasJSONControl: [...document.querySelectorAll("button, a")].some((element) => /download json/i.test(element.textContent || "")),
            hasPhraseBullet: /[·•]/.test(document.body.innerText),
            hasMetricSwitcher: Boolean(document.querySelector(".metric-toggle, [data-metric]"))
          });
        })()`,
        returnByValue: true,
      });
      if (rendered.result.value) reportUI = JSON.parse(rendered.result.value);
    } catch {
      // The previous execution context is destroyed during Blob navigation.
    }
    if (reportUI?.recommendations !== undefined && reportUI?.treemapTiles > 0 && reportUI?.imageSources > 0) break;
    await delay(100);
  }
  if (
    reportUI?.treemapTiles < 1 ||
    reportUI?.imageSources < 1 ||
    !reportUI?.binariesMatchData ||
    !reportUI?.binariesSorted ||
    !reportUI?.binariesComplete ||
    reportUI?.binaryOpportunityColumns !== 2 ||
    !reportUI?.recommendationsMatchData ||
    !reportUI?.linkingReviewsMatchData ||
    !reportUI?.linkingReviewMetricsAreScope ||
    reportUI?.staleFrameworkReviewTags > 0 ||
    !reportUI?.recommendationsCountMatchesData ||
    !reportUI?.recommendationsNavAccessible ||
    !reportUI?.recommendationsSorted ||
    !reportUI?.recommendationsMaterial ||
    reportUI?.recommendationIconsMissing > 0 ||
    reportUI?.recommendationExpanders !== reportUI?.expectedRecommendationExpanders ||
    !reportUI?.recommendationsAllExpandable ||
    !reportUI?.recommendationEvidenceMatches ||
    !reportUI?.duplicateEvidenceSemantics ||
    reportUI?.hasPotentialBadges ||
    reportUI?.overlappingTilePairs > 0 ||
    reportUI?.treemapLayers !== 1 ||
    reportUI?.hasStaleMapRecommendationUI ||
    !reportUI?.duplicateKeyMatchesData ||
    !reportUI?.duplicateKeyIsUnified ||
    !reportUI?.duplicationNodesAccessible ||
    !reportUI?.duplicateTaxonomyRemoved ||
    !reportUI?.imageDuplicateSummariesValid ||
    !reportUI?.architectureDuplicateSemantics ||
    !reportUI?.architectureDuplicateCopyClear ||
    reportUI?.bundleTreemapNavLabel !== "Bundle treemap" ||
    reportUI?.bundleTreemapHeader !== "Bundle treemap" ||
    reportUI?.undersizedDrillTargets > 0 ||
    reportUI?.nativeParentTitles > 0 ||
    reportUI?.blockingGroupFrames > 0 ||
    reportUI?.oversizedGroupHeaders > 0 ||
    reportUI?.reportNavCount !== 7 ||
    reportUI?.visibleReportNavCount !== reportUI?.expectedVisibleReportNavCount ||
    JSON.stringify(reportUI?.metricLabels) !== JSON.stringify(["Download","Install"]) ||
    reportUI?.hasInventory ||
    reportUI?.hasFileBrowser ||
    reportUI?.hasJSONControl ||
    reportUI?.hasPhraseBullet ||
    reportUI?.hasMetricSwitcher
  ) {
    throw new Error(
      `Standalone report did not render cleanly: ${JSON.stringify(reportUI)}.`,
    );
  }
  const recommendationInteraction = JSON.parse(
    (
      await command("Runtime.evaluate", {
        expression: `(() => {
          const recommendation = document.querySelector("#recommendations-list details.recommendation");
          if (!recommendation) return JSON.stringify({ available:false });
          const activeView = document.querySelector(".view.active")?.id;
          recommendation.querySelector(":scope > summary").click();
          const outerOpen = recommendation.open;
          const evidence = recommendation.querySelector("details.recommendation-evidence");
          if (evidence) evidence.querySelector(":scope > summary").click();
          const nestedOpen = evidence ? evidence.open : true;
          const stayedInView = document.querySelector(".view.active")?.id === activeView;
          if (evidence) evidence.open = false;
          recommendation.open = false;
          return JSON.stringify({available:true,outerOpen,nestedOpen,stayedInView});
        })()`,
        returnByValue: true,
      })
    ).result.value,
  );
  if (
    recommendationInteraction.available &&
    (!recommendationInteraction.outerOpen ||
      !recommendationInteraction.nestedOpen ||
      !recommendationInteraction.stayedInView)
  ) {
    throw new Error(
      `Recommendation expansion failed: ${JSON.stringify(recommendationInteraction)}.`,
    );
  }
  if (process.env.TEST_RECOMMENDATION_BATCH === "1") {
    const recommendationBatch = JSON.parse(
      (
        await command("Runtime.evaluate", {
          expression: `(() => {
            document.querySelector('[data-view="insights"]')?.click();
            const button = document.querySelector("#recommendations-list [data-recommendation-more]");
            if (!button) return JSON.stringify({ available:false });
            const recommendation = button.closest("details.recommendation");
            recommendation.open = true;
            const before = [...recommendation.querySelectorAll(".recommendation-evidence[hidden]")];
            const first = before[0];
            button.click();
            const after = recommendation.querySelectorAll(".recommendation-evidence[hidden]").length;
            const focused = document.activeElement === first || document.activeElement === first?.querySelector(":scope > summary");
            return JSON.stringify({
              available:true,
              before:before.length,
              after,
              revealed:before.length - after,
              focused,
            });
          })()`,
          returnByValue: true,
        })
      ).result.value,
    );
    if (
      !recommendationBatch.available ||
      recommendationBatch.revealed !== Math.min(20,recommendationBatch.before) ||
      !recommendationBatch.focused
    ) {
      throw new Error(
        `Recommendation evidence batching failed: ${JSON.stringify(recommendationBatch)}.`,
      );
    }
    await command("Runtime.evaluate", {
      expression: `document.querySelector('[data-view="map"]')?.click()`,
    });
    await delay(50);
  }
  const architectureDuplicateInteraction = JSON.parse(
    (
      await command("Runtime.evaluate", {
        expression: `(() => {
          document.querySelector('[data-view="architecture"]')?.click();
          const row = document.querySelector("#architecture-stack .architecture-duplicate-item");
          if (!row) return JSON.stringify({ available:false });
          row.querySelector(":scope > summary")?.click();
          const locations = row.querySelector(".architecture-location-list");
          const more = document.querySelector("#architecture-stack [data-architecture-more]");
          const moreTable = more?.closest(".architecture-table");
          const hiddenBefore = moreTable?.querySelectorAll(".architecture-duplicate-item[hidden]").length || 0;
          const firstHidden = moreTable?.querySelector(".architecture-duplicate-item[hidden]");
          more?.click();
          const hiddenAfter = moreTable?.querySelectorAll(".architecture-duplicate-item[hidden]").length || 0;
          return JSON.stringify({
            available:true,
            open:row.open,
            locationCount:locations?.querySelectorAll("code").length || 0,
            locationsVisible:Boolean(locations?.getBoundingClientRect().height),
            batchingAvailable:Boolean(more),
            batchBefore:hiddenBefore,
            batchRevealed:hiddenBefore - hiddenAfter,
            batchFocused:!more || document.activeElement === firstHidden?.querySelector(":scope > summary"),
          });
        })()`,
        returnByValue: true,
      })
    ).result.value,
  );
  if (
    architectureDuplicateInteraction.available &&
    (!architectureDuplicateInteraction.open ||
      architectureDuplicateInteraction.locationCount < 2 ||
      !architectureDuplicateInteraction.locationsVisible ||
      (architectureDuplicateInteraction.batchingAvailable &&
        (architectureDuplicateInteraction.batchRevealed !== Math.min(50,architectureDuplicateInteraction.batchBefore) ||
          !architectureDuplicateInteraction.batchFocused)))
  ) {
    throw new Error(
      `Architecture duplicate disclosure failed: ${JSON.stringify(architectureDuplicateInteraction)}.`,
    );
  }
  await command("Runtime.evaluate", {
    expression: `document.querySelector('[data-view="map"]')?.click()`,
  });
  await delay(50);
  const mapInteraction = JSON.parse(
    (
      await command("Runtime.evaluate", {
        expression: `(() => {
          const label = document.querySelector("#bundle-map .treemap-group-label");
          if (!label) return JSON.stringify({ available:false });
          const frame = [...document.querySelectorAll("#bundle-map .treemap-group")]
            .find((element) => element.dataset.nodePath === label.dataset.nodePath);
          label.focus();
          label.dispatchEvent(new Event("focus"));
          const outline = document.querySelector("#bundle-map .treemap-hover-frame");
          const outlineRect = outline.getBoundingClientRect();
          const frameRect = frame?.getBoundingClientRect();
          const outlineMatches = Boolean(frameRect) && [
            outlineRect.left - frameRect.left,
            outlineRect.top - frameRect.top,
            outlineRect.width - frameRect.width,
            outlineRect.height - frameRect.height,
          ].every((value) => Math.abs(value) <= 1);
          const outlineVisible = outline?.classList.contains("visible") === true;
          const outlinePointerEvents = outline ? getComputedStyle(outline).pointerEvents : "";
          label.click();
          const layer = document.querySelector("#bundle-map .treemap-layer");
          const animation = layer?.getAnimations()[0];
          const frames = animation?.effect?.getKeyframes?.() || [];
          return JSON.stringify({
            available:true,
            reducedMotion:matchMedia("(prefers-reduced-motion: reduce)").matches,
            outlineMatches,
            outlineVisible,
            outlinePointerEvents,
            animationStarted:Boolean(animation),
            animationUsesClip:frames.some((frame) => String(frame.clipPath || "").startsWith("inset(")),
            animationStretches:frames.some((frame) => /scale\\([^,]+,/.test(String(frame.transform || ""))),
            animatingClass:document.querySelector("#bundle-map").classList.contains("animating"),
          });
        })()`,
        returnByValue: true,
      })
    ).result.value,
  );
  await delay(240);
  const mapInteractionSettled = JSON.parse(
    (
      await command("Runtime.evaluate", {
        expression: `JSON.stringify({
          animationCount:document.querySelector("#bundle-map .treemap-layer")?.getAnimations().length,
          animatingClass:document.querySelector("#bundle-map").classList.contains("animating"),
          backVisible:!document.querySelector("#back-button").hidden,
          backFocused:document.activeElement?.id === "back-button",
        })`,
        returnByValue: true,
      })
    ).result.value,
  );
  const animationFailed = mapInteraction.reducedMotion
    ? mapInteraction.animationStarted || mapInteraction.animatingClass
    : !mapInteraction.animationStarted ||
      !mapInteraction.animationUsesClip ||
      mapInteraction.animationStretches ||
      !mapInteraction.animatingClass;
  if (
    mapInteraction.available &&
    (!mapInteraction.outlineMatches ||
      !mapInteraction.outlineVisible ||
      mapInteraction.outlinePointerEvents !== "none" ||
      animationFailed ||
      mapInteractionSettled.animationCount !== 0 ||
      mapInteractionSettled.animatingClass ||
      !mapInteractionSettled.backVisible ||
      !mapInteractionSettled.backFocused)
  ) {
    throw new Error(
      `Treemap interaction failed: ${JSON.stringify({ mapInteraction, mapInteractionSettled })}.`,
    );
  }
  if (mapInteraction.available) {
    await command("Runtime.evaluate", {
      expression: `document.querySelector("#back-button")?.click()`,
    });
    await delay(240);
  }
  const screenshotView = process.env.SCREENSHOT_VIEW || "";
  if (["map", "insights", "images", "architecture", "binaries", "capabilities", "locales"].includes(screenshotView)) {
    await command("Runtime.evaluate", {
      expression: `document.querySelector('[data-view="${screenshotView}"]')?.click()`,
    });
    await delay(250);
  }
  if (process.env.OPEN_RECOMMENDATION_ID || process.env.OPEN_FIRST_RECOMMENDATION === "1") {
    await command("Runtime.evaluate", {
      expression: `(() => {
        const wanted = ${JSON.stringify(process.env.OPEN_RECOMMENDATION_ID || "")};
        const recommendation = wanted
          ? document.querySelector('#recommendations-list .recommendation[data-insight-id="' + CSS.escape(wanted) + '"]')
          : document.querySelector("#recommendations-list details.recommendation");
        if (recommendation instanceof HTMLDetailsElement) {
          recommendation.open = true;
          if (${JSON.stringify(process.env.OPEN_FIRST_RECOMMENDATION_ITEM === "1")}) {
            const evidence = recommendation.querySelector("details.recommendation-evidence");
            if (evidence instanceof HTMLDetailsElement) evidence.open = true;
          }
          recommendation.scrollIntoView({ block:"start" });
        }
      })()`,
    });
    await delay(150);
  }
  if (screenshotView === "binaries" && process.env.OPEN_FIRST_BINARY === "1") {
    await command("Runtime.evaluate", {
      expression: `document.querySelector("#binaries-stack .binary-item")?.setAttribute("open", "")`,
    });
    await delay(150);
  }
  if (screenshotView === "architecture" && process.env.OPEN_FIRST_ARCHITECTURE_DUPLICATE === "1") {
    await command("Runtime.evaluate", {
      expression: `(() => {
        const row = document.querySelector("#architecture-stack .architecture-duplicate-item");
        if (row instanceof HTMLDetailsElement) {
          row.open = true;
          row.scrollIntoView({ block:"start" });
        }
      })()`,
    });
    await delay(150);
  }
  if (process.env.IMAGE_SOURCE_ID) {
    await command("Runtime.evaluate", {
      expression: `document.querySelector('#image-sources [data-source=${JSON.stringify(process.env.IMAGE_SOURCE_ID)}]')?.click()`,
    });
    await delay(150);
  }
  if (process.env.IMAGE_ASSET_NAME) {
    await command("Runtime.evaluate", {
      expression: `(() => {
        const wanted = ${JSON.stringify(process.env.IMAGE_ASSET_NAME)};
        const match = [...document.querySelectorAll("#image-list .image-asset")]
          .find((element) => element.querySelector("summary strong")?.textContent === wanted);
        match?.setAttribute("open", "");
        match?.scrollIntoView({ block:"start" });
      })()`,
    });
    await delay(150);
  }
  if (process.env.OPEN_FIRST_IMAGE_ASSET === "1") {
    await command("Runtime.evaluate", {
      expression: `document.querySelector("#image-list .image-asset")?.setAttribute("open", "")`,
    });
    await delay(150);
  }
  if (process.env.REPORT_HTML_PATH) {
    writeFileSync(resolve(process.env.REPORT_HTML_PATH), exported.html);
  }
  if (process.env.REPORT_JSON_PATH) {
    writeFileSync(
      resolve(process.env.REPORT_JSON_PATH),
      `${JSON.stringify(analysis, null, 2)}\n`,
    );
  }
  if (process.env.SCREENSHOT_PATH) {
    await delay(1000);
    const screenshot = await command("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
    });
    writeFileSync(resolve(process.env.SCREENSHOT_PATH), screenshot.data, "base64");
  }
  process.stdout.write(`${JSON.stringify(state)}\n`);
} finally {
  if (socket?.readyState === WebSocket.OPEN) socket.close();
  chrome.kill("SIGTERM");
  if (chrome.exitCode === null) {
    await Promise.race([
      new Promise((resolveValue) => chrome.once("exit", resolveValue)),
      delay(3000),
    ]);
  }
  rmSync(profile, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 100,
  });
}
