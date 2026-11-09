/* ═══════════════════════════════════════════════════════════════
   VAULT — application logic
   Local-first gallery. Images live in IndexedDB on this device.
   Optional AES-256-GCM vault encryption (PBKDF2-derived key,
   held in memory only while unlocked).
   ═══════════════════════════════════════════════════════════════ */

"use strict";

/* ── Tiny helpers ─────────────────────────────────────────── */
const $ = (sel) => document.querySelector(sel);
const uid = () => crypto.randomUUID();

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log10(n) / 3), u.length - 1);
  const v = n / Math.pow(1000, i);
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
}
function fmtDate(ts) {
  return new Date(ts).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}
function esc(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ── IndexedDB ────────────────────────────────────────────── */
const DB_NAME = "vault-gallery";
const STORE_ITEMS = "items";
const STORE_META = "meta";

function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_ITEMS)) db.createObjectStore(STORE_ITEMS, { keyPath: "id" });
      if (!db.objectStoreNames.contains(STORE_META)) db.createObjectStore(STORE_META);
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function idbPut(store, value, key) {
  const db = await dbPromise;
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readwrite");
    const r = key === undefined ? tx.objectStore(store).put(value) : tx.objectStore(store).put(value, key);
    r.onsuccess = () => res();
    r.onerror = () => rej(r.error);
  });
}
async function idbGetAll(store) {
  const db = await dbPromise;
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readonly");
    const r = tx.objectStore(store).getAll();
    r.onsuccess = () => res(r.result || []);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(store, key) {
  const db = await dbPromise;
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readonly");
    const r = tx.objectStore(store).get(key);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbDelete(store, key) {
  const db = await dbPromise;
  return new Promise((res, rej) => {
    const tx = db.transaction(store, "readwrite");
    const r = tx.objectStore(store).delete(key);
    r.onsuccess = () => res();
    r.onerror = () => rej(r.error);
  });
}

const dbPromise = openDB();

/* ── Crypto ───────────────────────────────────────────────── */
const PBKDF2_ITERS = 600000;
const VAULT_KEY = "vault";

async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptBuf(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { iv, data: ct };
}
async function decryptBuf(key, iv, data) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
}
const enc = new TextEncoder();

/* ── State ────────────────────────────────────────────────── */
const SORTS = [
  ["newest", "Newest"],
  ["oldest", "Oldest"],
  ["name", "A–Z"],
  ["favorites", "Favorites"],
];
const state = {
  items: [],
  key: null,
  cfg: { encrypted: false },
  query: "",
  sort: "newest",
  urls: new Map(),
  lightboxId: null,
  locked: true,
};

/* ── Record (de)serialization for encrypted storage ────────── */
function metaOf(rec) {
  const { blob, thumb, ...meta } = rec;
  return meta;
}
async function encryptRecord(rec) {
  const metaEnc = await encryptBuf(state.key, enc.encode(JSON.stringify(metaOf(rec))));
  const blobEnc = await encryptBuf(state.key, await rec.blob.arrayBuffer());
  const thumbEnc = rec.thumb ? await encryptBuf(state.key, await rec.thumb.arrayBuffer()) : null;
  return { id: rec.id, encrypted: true, metaEnc, blobEnc, thumbEnc };
}
async function decryptRecord(row) {
  const meta = JSON.parse(new TextDecoder().decode(await decryptBuf(state.key, row.metaEnc.iv, row.metaEnc.data)));
  const blob = new Blob([await decryptBuf(state.key, row.blobEnc.iv, row.blobEnc.data)], { type: meta.type });
  let thumb = null;
  if (row.thumbEnc) thumb = new Blob([await decryptBuf(state.key, row.thumbEnc.iv, row.thumbEnc.data)], { type: "image/webp" });
  return { ...meta, blob, thumb: thumb || blob };
}
async function putRecord(rec) {
  const row = state.cfg.encrypted ? await encryptRecord(rec) : rec;
  await idbPut(STORE_ITEMS, row);
}
async function loadItems() {
  const rows = await idbGetAll(STORE_ITEMS);
  const out = [];
  for (const row of rows) {
    out.push(row.encrypted ? await decryptRecord(row) : row);
  }
  out.sort((a, b) => b.addedAt - a.addedAt);
  return out;
}

/* ── Object URLs ──────────────────────────────────────────── */
function thumbURL(rec) {
  let u = state.urls.get(rec.id);
  if (!u) {
    u = { thumb: URL.createObjectURL(rec.thumb), full: URL.createObjectURL(rec.blob) };
    state.urls.set(rec.id, u);
  }
  return u.thumb;
}
function fullURL(rec) {
  thumbURL(rec);
  return state.urls.get(rec.id).full;
}
function dropURLs(id) {
  const u = state.urls.get(id);
  if (u) {
    URL.revokeObjectURL(u.thumb);
    URL.revokeObjectURL(u.full);
    state.urls.delete(id);
  }
}
function dropAllURLs() {
  for (const id of state.urls.keys()) dropURLs(id);
}

/* ── Toasts ───────────────────────────────────────────────── */
function toast(msg, ms = 2800) {
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>' +
    esc(msg);
  $("#toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
  }, ms);
}

/* ── Image processing ─────────────────────────────────────── */
async function loadBitmap(file) {
  if ("createImageBitmap" in window) {
    try { return await createImageBitmap(file); } catch (_) { /* fall through */ }
  }
  return new Promise((res, rej) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); res(img); };
    img.onerror = () => { URL.revokeObjectURL(url); rej(new Error("decode failed")); };
    img.src = url;
  });
}
function makeThumb(bitmap, maxEdge = 560) {
  const scale = Math.min(1, maxEdge / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(bitmap, 0, 0, w, h);
  return new Promise((res) => {
    canvas.toBlob(
      (b) => {
        if (b && b.type === "image/webp") return res(b);
        const c2 = document.createElement("canvas");
        c2.width = w; c2.height = h;
        const ctx2 = c2.getContext("2d");
        ctx2.fillStyle = "#141210";
        ctx2.fillRect(0, 0, w, h);
        ctx2.drawImage(bitmap, 0, 0, w, h);
        c2.toBlob((b2) => res(b2 || b), "image/jpeg", 0.82);
      },
      "image/webp",
      0.82
    );
  });
}

/* ── Upload ───────────────────────────────────────────────── */
async function addFiles(fileList) {
  const files = [...fileList].filter((f) => f.type.startsWith("image/"));
  if (!files.length) return;
  const added = [];
  for (const file of files) {
    try {
      const bmp = await loadBitmap(file);
      const w = bmp.width;
      const h = bmp.height;
      const thumb = await makeThumb(bmp);
      if (bmp.close) bmp.close();
      const rec = {
        id: uid(),
        name: file.name.replace(/\.[a-z0-9]+$/i, "") || "Untitled",
        type: file.type || "image/*",
        size: file.size,
        w,
        h,
        addedAt: Date.now(),
        caption: "",
        tags: [],
        favorite: false,
        blob: file,
        thumb,
      };
      await putRecord(rec);
      state.items.unshift(rec);
      added.push(rec);
    } catch (err) {
      console.error(err);
      toast('Couldn\'t read "' + file.name + '"');
    }
  }
  if (added.length) {
    render();
    toast(added.length === 1 ? "Added to the vault" : added.length + " added to the vault");
  }
}

/* ── Rendering ────────────────────────────────────────────── */
function visibleItems() {
  let list = state.items;
  const q = state.query.trim().toLowerCase();
  if (q) {
    list = list.filter((r) =>
      (r.name + " " + r.caption + " " + (r.tags || []).join(" ")).toLowerCase().includes(q)
    );
  }
  const sorters = {
    newest: (a, b) => b.addedAt - a.addedAt,
    oldest: (a, b) => a.addedAt - b.addedAt,
    name: (a, b) => a.name.localeCompare(b.name),
    favorites: (a, b) => (b.favorite - a.favorite) || (b.addedAt - a.addedAt),
  };
  return [...list].sort(sorters[state.sort]);
}

function render() {
  const items = state.items;
  const total = items.length;
  const favs = items.filter((r) => r.favorite).length;
  const bytes = items.reduce((s, r) => s + (r.size || 0), 0);

  $("#artifactCount").textContent = total
    ? total + (total === 1 ? " artifact" : " artifacts") + (favs ? " · " + favs + " ★" : "") + " · " + fmtBytes(bytes)
    : "";

  const vis = visibleItems();
  const empty = total === 0;
  $("#emptyState").hidden = !empty;
  $("#gridSection").hidden = empty;
  $("#noResults").hidden = !(empty === false && vis.length === 0);
  $("#fab").hidden = empty;

  const grid = $("#grid");
  grid.innerHTML = "";
  vis.forEach((rec, i) => {
    const cell = document.createElement("button");
    cell.className = "cell";
    cell.style.setProperty("--i", i);
    cell.setAttribute("aria-label", "Open " + rec.name);
    const chips = (rec.tags || []).slice(0, 3).map((t) => '<span class="tag-chip">#' + esc(t) + "</span>").join("");
    const cap = (chips ? " " : "") + (rec.caption ? esc(rec.caption) : esc(rec.name));
    cell.innerHTML =
      '<img src="' + thumbURL(rec) + '" alt="' + esc(rec.name) + '" loading="lazy" />' +
      '<span class="cell-fav' + (rec.favorite ? " active filled" : "") + '" aria-hidden="true">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.8l2.5 5.2 5.7.8-4.1 4 1 5.6L12 16.7l-5.1 2.7 1-5.6-4.1-4 5.7-.8L12 3.8z"/></svg></span>' +
      '<span class="cell-caption' + (rec.caption ? " has-caption" : "") + '">' + chips + cap + "</span>";
    cell.addEventListener("click", () => openLightbox(rec.id, cell));
    grid.appendChild(cell);
  });
}

/* ── 2.5D tilt ────────────────────────────────────────────── */
function wireTilt() {
  const grid = $("#grid");
  let active = null;
  const reset = () => {
    if (!active) return;
    active.style.setProperty("--rx", "0deg");
    active.style.setProperty("--ry", "0deg");
    active.style.setProperty("--tz", "0px");
    active = null;
  };
  grid.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch") return;
    const cell = e.target.closest(".cell");
    if (cell !== active) reset();
    if (!cell) return;
    active = cell;
    const r = cell.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    cell.style.setProperty("--rx", (-py * 10).toFixed(2) + "deg");
    cell.style.setProperty("--ry", (px * 12).toFixed(2) + "deg");
    cell.style.setProperty("--tz", "14px");
  }, { passive: true });
  grid.addEventListener("pointerleave", reset);
}

/* ── HUD auto-hide ────────────────────────────────────────── */
let idleTimer = null;
function pokeIdle() {
  document.body.classList.remove("idle");
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    const modalOpen = !$("#securityModal").hidden || !$("#confirmModal").hidden;
    if (!typing && !modalOpen) document.body.classList.add("idle");
  }, 2600);
}

/* ── Lightbox ─────────────────────────────────────────────── */
function lbList() { return visibleItems(); }
function currentRec() { return state.items.find((r) => r.id === state.lightboxId); }

function openLightbox(id, fromCell) {
  state.lightboxId = id;
  const rec = currentRec();
  if (!rec) return;
  $("#lightbox").hidden = false;
  document.body.classList.add("lb-open");
  document.body.style.overflow = "hidden";
  updateLightbox();
  pokeIdle();

  /* FLIP — the image flies out of the grid cell into the center */
  if (fromCell) {
    const img = $("#lbImage");
    const fromImg = fromCell.querySelector("img");
    (async () => {
      try { await img.decode(); } catch (_) { /* already decoded */ }
      requestAnimationFrame(() => {
        if (!fromImg.isConnected) return;
        const from = fromImg.getBoundingClientRect();
        const to = img.getBoundingClientRect();
        if (!to.width || !to.height) return;
        const dx = from.left + from.width / 2 - (to.left + to.width / 2);
        const dy = from.top + from.height / 2 - (to.top + to.height / 2);
        const sx = from.width / to.width;
        const sy = from.height / to.height;
        img.style.transition = "none";
        img.style.transform = "translate(" + dx.toFixed(1) + "px, " + dy.toFixed(1) + "px) scale(" + sx.toFixed(4) + ", " + sy.toFixed(4) + ")";
        img.getBoundingClientRect(); // force reflow
        img.style.transition = "";
        img.style.transform = "";
      });
    })();
  }
}
function closeLightbox() {
  state.lightboxId = null;
  $("#lightbox").hidden = true;
  document.body.classList.remove("lb-open");
  document.body.style.overflow = "";
}
function stepLightbox(dir) {
  const list = lbList();
  const idx = list.findIndex((r) => r.id === state.lightboxId);
  if (idx === -1 || !list.length) return;
  const next = list[(idx + dir + list.length) % list.length];
  state.lightboxId = next.id;
  updateLightbox();
}
function updateLightbox() {
  const rec = currentRec();
  if (!rec) return closeLightbox();
  const list = lbList();
  const idx = list.findIndex((r) => r.id === rec.id);

  const img = $("#lbImage");
  img.src = fullURL(rec);
  img.alt = rec.caption || rec.name;
  $("#lbName").textContent = rec.name;
  $("#lbIndex").textContent = idx + 1 + " / " + list.length;
  $("#lbDetails").textContent =
    fmtDate(rec.addedAt) + " · " + rec.w + "×" + rec.h + " · " + fmtBytes(rec.size);
  $("#lbCaption").value = rec.caption || "";
  $("#lbTags").value = (rec.tags || []).join(", ");
  $("#lbFavorite").classList.toggle("active", !!rec.favorite);
  $("#lbFavorite").setAttribute("aria-pressed", String(!!rec.favorite));
}
async function saveLightboxMeta() {
  const rec = currentRec();
  if (!rec) return;
  const caption = $("#lbCaption").value.trim();
  const tags = $("#lbTags").value.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean);
  if (caption === rec.caption && JSON.stringify(tags) === JSON.stringify(rec.tags || [])) return;
  rec.caption = caption;
  rec.tags = tags;
  await putRecord(rec);
  render();
}
async function toggleFavorite() {
  const rec = currentRec();
  if (!rec) return;
  rec.favorite = !rec.favorite;
  await putRecord(rec);
  render();
  updateLightbox();
}

/* ── Security / vault ─────────────────────────────────────── */
async function readCfg() {
  const cfg = await idbGet(STORE_META, VAULT_KEY);
  state.cfg = cfg && cfg.encrypted ? cfg : { encrypted: false };
}
async function writeCfg() {
  await idbPut(STORE_META, state.cfg, VAULT_KEY);
}

async function lockVault() {
  dropAllURLs();
  state.items = [];
  state.key = null;
  state.locked = true;
  state.lightboxId = null;
  closeLightbox();
  $("#grid").innerHTML = "";
  $("#emptyState").hidden = true;
  $("#gridSection").hidden = true;
  $("#unlockPass").value = "";
  $("#unlockError").hidden = true;
  $("#lockScreen").hidden = false;
  $("#lockBtn").hidden = true;
  setTimeout(() => $("#unlockPass").focus(), 60);
}

async function tryUnlock(pass) {
  const salt = Uint8Array.from(atob(state.cfg.salt), (c) => c.charCodeAt(0));
  const key = await deriveKey(pass, salt);
  try {
    const plain = await decryptBuf(key, new Uint8Array(state.cfg.verifier.iv), state.cfg.verifier.data);
    if (new TextDecoder().decode(plain) !== "vault-ok") throw new Error("bad verifier");
  } catch (_) {
    const err = $("#unlockError");
    err.hidden = false;
    err.style.animation = "none";
    err.getBoundingClientRect();
    err.style.animation = "";
    return;
  }
  state.key = key;
  state.locked = false;
  state.items = await loadItems();
  $("#lockScreen").hidden = true;
  $("#lockBtn").hidden = !state.cfg.encrypted;
  render();
}

async function enableEncryption(newPass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(newPass, salt);
  const verifier = await encryptBuf(key, enc.encode("vault-ok"));
  state.key = key;
  state.cfg = { encrypted: true, salt: btoa(String.fromCharCode(...salt)), verifier };
  for (const rec of state.items) await putRecord(rec);
  await writeCfg();
  $("#lockBtn").hidden = false;
  render();
  toast("Vault encrypted — AES-256-GCM active");
}
async function disableEncryption() {
  state.cfg = { encrypted: false };
  state.key = null;
  for (const rec of state.items) await putRecord(rec);
  await idbPut(STORE_META, state.cfg, VAULT_KEY);
  $("#lockBtn").hidden = true;
  toast("Encryption removed — images stay local");
}

/* ── Export / import ──────────────────────────────────────── */
function blobToDataURL(blob) {
  return new Promise((res) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.readAsDataURL(blob);
  });
}
async function exportArchive() {
  if (!state.items.length) return toast("Nothing to export yet");
  const payload = {
    app: "vault-gallery",
    version: 1,
    exportedAt: new Date().toISOString(),
    items: await Promise.all(
      state.items.map(async (r) => ({
        id: r.id, name: r.name, type: r.type, size: r.size, w: r.w, h: r.h,
        addedAt: r.addedAt, caption: r.caption, tags: r.tags, favorite: r.favorite,
        data: await blobToDataURL(r.blob),
      }))
    ),
  };
  const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vault-archive-" + new Date().toISOString().slice(0, 10) + ".json";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Archive exported (" + fmtBytes(blob.size) + ")");
}
async function importArchive(file) {
  let payload;
  try { payload = JSON.parse(await file.text()); } catch (_) { return toast("That file isn't a valid archive"); }
  if (payload.app !== "vault-gallery" || !Array.isArray(payload.items)) return toast("That file isn't a vault archive");
  let count = 0;
  for (const it of payload.items) {
    if (state.items.some((r) => r.id === it.id)) continue;
    try {
      const blob = await (await fetch(it.data)).blob();
      const bmp = await loadBitmap(blob);
      const w = bmp.width;
      const h = bmp.height;
      const thumb = await makeThumb(bmp);
      if (bmp.close) bmp.close();
      const rec = {
        id: it.id, name: it.name, type: it.type, size: blob.size, w: it.w || w, h: it.h || h,
        addedAt: it.addedAt || Date.now(), caption: it.caption || "", tags: it.tags || [],
        favorite: !!it.favorite, blob, thumb,
      };
      await putRecord(rec);
      state.items.push(rec);
      count++;
    } catch (err) { console.error(err); }
  }
  if (count) { render(); toast("Restored " + count + (count === 1 ? " artifact" : " artifacts")); }
  else toast("Nothing new to restore");
}

/* ── Wiring ───────────────────────────────────────────────── */
function wire() {
  /* Upload */
  const pick = () => $("#fileInput").click();
  $("#uploadBtn").addEventListener("click", pick);
  $("#emptyUploadBtn").addEventListener("click", pick);
  $("#fab").addEventListener("click", pick);
  $("#fileInput").addEventListener("change", (e) => { addFiles(e.target.files); e.target.value = ""; });

  /* Search & sort */
  $("#searchInput").addEventListener("input", (e) => { state.query = e.target.value; render(); });
  $("#sortBtn").addEventListener("click", () => {
    const i = SORTS.findIndex(([k]) => k === state.sort);
    const [key, label] = SORTS[(i + 1) % SORTS.length];
    state.sort = key;
    $("#sortBtn").textContent = label;
    render();
  });
  $("#sortBtn").textContent = SORTS[0][1];

  /* HUD idle */
  ["pointermove", "pointerdown", "keydown", "scroll", "focusin"].forEach((ev) =>
    window.addEventListener(ev, pokeIdle, { passive: true })
  );
  pokeIdle();

  /* Drag & drop */
  let dragDepth = 0;
  const overlay = $("#dropOverlay");
  window.addEventListener("dragenter", (e) => {
    if (![...(e.dataTransfer?.types || [])].includes("Files")) return;
    e.preventDefault();
    dragDepth++;
    overlay.classList.add("active");
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragleave", (e) => {
    if (--dragDepth <= 0) { dragDepth = 0; overlay.classList.remove("active"); }
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    overlay.classList.remove("active");
    if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
  });

  /* Paste */
  window.addEventListener("paste", (e) => {
    if (state.locked) return;
    const files = [...(e.clipboardData?.files || [])].filter((f) => f.type.startsWith("image/"));
    if (files.length) { e.preventDefault(); addFiles(files); }
  });

  /* Lightbox */
  $("#lbClose").addEventListener("click", closeLightbox);
  $(".lb-backdrop").addEventListener("click", closeLightbox);
  $("#lbPrev").addEventListener("click", () => stepLightbox(-1));
  $("#lbNext").addEventListener("click", () => stepLightbox(1));
  $("#lbFavorite").addEventListener("click", toggleFavorite);
  $("#lbCaption").addEventListener("change", saveLightboxMeta);
  $("#lbTags").addEventListener("change", saveLightboxMeta);
  $("#lbDownload").addEventListener("click", () => {
    const rec = currentRec();
    if (!rec) return;
    const a = document.createElement("a");
    a.href = fullURL(rec);
    a.download = rec.name + (rec.type.includes("png") ? ".png" : rec.type.includes("webp") ? ".webp" : rec.type.includes("gif") ? ".gif" : ".jpg");
    a.click();
  });
  $("#lbDelete").addEventListener("click", () => { $("#confirmModal").hidden = false; });
  $("#confirmDeleteBtn").addEventListener("click", async () => {
    const rec = currentRec();
    $("#confirmModal").hidden = true;
    if (!rec) return;
    closeLightbox();
    await idbDelete(STORE_ITEMS, rec.id);
    dropURLs(rec.id);
    state.items = state.items.filter((r) => r.id !== rec.id);
    render();
    toast('Removed "' + rec.name + '"');
  });

  /* Modals */
  $("#securityBtn").addEventListener("click", () => { refreshSecurityUI(); $("#securityModal").hidden = false; });
  document.querySelectorAll("[data-close-modal]").forEach((el) =>
    el.addEventListener("click", () => {
      $("#securityModal").hidden = true;
      $("#confirmModal").hidden = true;
      $("#passForm").hidden = true;
    })
  );

  /* Security */
  $("#encToggleBtn").addEventListener("click", () => {
    const form = $("#passForm");
    if (form.hidden) {
      const isOn = state.cfg.encrypted;
      $("#passFormTitle").textContent = isOn ? "Change or remove the passphrase" : "Set a vault passphrase";
      $("#curPass").parentElement.hidden = !isOn;
      $("#curPassLabel").textContent = "Current passphrase";
      $("#curPass").value = "";
      $("#newPass").value = "";
      $("#newPass2").value = "";
      form.hidden = false;
      $("#newPass").focus();
    } else {
      form.hidden = true;
    }
  });
  $("#passForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const isOn = state.cfg.encrypted;
    const cur = $("#curPass").value;
    const p1 = $("#newPass").value;
    const p2 = $("#newPass2").value;
    if (isOn) {
      if (!cur) return toast("Enter your current passphrase");
      try {
        const salt = Uint8Array.from(atob(state.cfg.salt), (c) => c.charCodeAt(0));
        const key = await deriveKey(cur, salt);
        const plain = new TextDecoder().decode(await decryptBuf(key, new Uint8Array(state.cfg.verifier.iv), state.cfg.verifier.data));
        if (plain !== "vault-ok") throw new Error();
      } catch (_) {
        return toast("Current passphrase is incorrect");
      }
    }
    if (p1.length < 8) return toast("Use at least 8 characters — longer is better");
    if (p1 !== p2) return toast("Passphrases don't match");
    await enableEncryption(p1);
    $("#passForm").hidden = true;
    refreshSecurityUI();
  });
  document.querySelector("[data-cancel-pass]").addEventListener("click", () => { $("#passForm").hidden = true; });

  $("#exportBtn").addEventListener("click", exportArchive);
  $("#importBtn").addEventListener("click", () => $("#importInput").click());
  $("#importInput").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (f) importArchive(f);
    e.target.value = "";
  });

  /* Lock */
  $("#lockBtn").addEventListener("click", lockVault);
  $("#unlockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pass = $("#unlockPass").value;
    if (pass) await tryUnlock(pass);
  });

  /* Keyboard */
  window.addEventListener("keydown", (e) => {
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    const lbOpen = !$("#lightbox").hidden;
    if (e.key === "/" && !typing && !lbOpen) {
      e.preventDefault();
      $("#searchInput").focus();
      return;
    }
    if (!lbOpen) {
      if (e.key === "Escape") {
        if (typing) document.activeElement.blur();
        $("#securityModal").hidden = true;
        $("#confirmModal").hidden = true;
        $("#passForm").hidden = true;
      }
      return;
    }
    switch (e.key) {
      case "ArrowLeft": stepLightbox(-1); break;
      case "ArrowRight": stepLightbox(1); break;
      case "Escape": closeLightbox(); break;
      case "f": case "F": if (!typing) toggleFavorite(); break;
      case "Delete": case "Backspace": if (!typing) $("#confirmModal").hidden = false; break;
    }
  });

  /* Idle auto-lock (10 minutes) for encrypted vaults */
  let lockTimer;
  const resetLock = () => {
    clearTimeout(lockTimer);
    if (state.cfg.encrypted && !state.locked) {
      lockTimer = setTimeout(lockVault, 10 * 60 * 1000);
    }
  };
  ["pointerdown", "keydown"].forEach((ev) =>
    window.addEventListener(ev, resetLock, { passive: true })
  );
  resetLock();

  wireTilt();
}

function refreshSecurityUI() {
  const isOn = state.cfg.encrypted;
  const btn = $("#encToggleBtn");
  btn.textContent = isOn ? "Manage" : "Enable";
  btn.className = "btn " + (isOn ? "btn-ghost" : "btn-gold");
  $("#secStatus").textContent = isOn
    ? "On — AES-256-GCM, key in memory only"
    : "Off — images stored locally, unencrypted";
}

/* ── Boot ─────────────────────────────────────────────────── */
(async function boot() {
  wire();
  try {
    await readCfg();
  } catch (err) {
    console.error(err);
  }
  if (state.cfg.encrypted) {
    await lockVault();
  } else {
    state.locked = false;
    try {
      state.items = await loadItems();
    } catch (err) {
      console.error(err);
      toast("Couldn't read local storage");
    }
    render();
  }
})();
