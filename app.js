/* ═══════════════════════════════════════════════════════════════
   VAULT — application logic
   A minimal 3D world of images. Local-first gallery:
   images live in IndexedDB on this device, optionally encrypted
   with AES-256-GCM (PBKDF2-derived key, memory-only while unlocked).
   ═══════════════════════════════════════════════════════════════ */

import * as THREE from "three";

/* ── Tiny helpers ─────────────────────────────────────────── */
const $ = (sel) => document.querySelector(sel);
const uid = () => crypto.randomUUID();
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

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

/* ── Crypto (AES-256-GCM vault) ───────────────────────────── */
const PBKDF2_ITERS = 600000;
const VAULT_KEY = "vault";
const enc = new TextEncoder();
const dec = new TextDecoder();

async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
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
  return { iv, ct };
}
async function decryptBuf(key, iv, data) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, key, data);
}

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
  const { iv, ct } = await encryptBuf(state.key, await rec.blob.arrayBuffer());
  const { iv: tiv, ct: tct } = await encryptBuf(state.key, await rec.thumb.arrayBuffer());
  return { ...metaOf(rec), iv, ct, tiv, tct };
}
async function decryptRecord(row) {
  const blob = new Blob([await decryptBuf(state.key, row.iv, row.ct)], { type: row.type });
  const thumb = new Blob([await decryptBuf(state.key, row.tiv, row.tct)], { type: "image/webp" });
  const { iv, ct, tiv, tct, ...meta } = row;
  return { ...meta, blob, thumb };
}
async function putRecord(rec) {
  const row = state.key ? await encryptRecord(rec) : rec;
  await idbPut(STORE_ITEMS, row);
}
async function loadItems() {
  const rows = await idbGetAll(STORE_ITEMS);
  if (!state.key) return rows;
  const out = [];
  for (const row of rows) {
    try { out.push(await decryptRecord(row)); } catch (err) { console.error(err); }
  }
  return out;
}

/* ── Object-URL cache (memory only, never persisted) ───────── */
function thumbURL(rec) {
  if (!state.urls.has(rec.id)) state.urls.set(rec.id, {});
  const u = state.urls.get(rec.id);
  if (!u.thumb) u.thumb = URL.createObjectURL(rec.thumb);
  return u.thumb;
}
function fullURL(rec) {
  if (!state.urls.has(rec.id)) state.urls.set(rec.id, {});
  const u = state.urls.get(rec.id);
  if (!u.full) u.full = URL.createObjectURL(rec.blob);
  return u.full;
}
function dropURLs(id) {
  const u = state.urls.get(id);
  if (u) { if (u.thumb) URL.revokeObjectURL(u.thumb); if (u.full) URL.revokeObjectURL(u.full); }
  state.urls.delete(id);
}
function dropAllURLs() {
  for (const id of [...state.urls.keys()]) dropURLs(id);
}

/* ── Toasts ───────────────────────────────────────────────── */
function toast(msg, ms = 2600) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  $("#toasts").appendChild(el);
  requestAnimationFrame(() => el.classList.add("in"));
  setTimeout(() => {
    el.classList.remove("in");
    setTimeout(() => el.remove(), 400);
  }, ms);
}

/* ── Image intake ─────────────────────────────────────────── */
async function loadBitmap(file) {
  if ("createImageBitmap" in window) return createImageBitmap(file);
  return new Promise((res, rej) => {
    const img = new Image();
    img.onload = () => res(img);
    img.onerror = rej;
    img.src = URL.createObjectURL(file);
  });
}
function makeThumb(bitmap, maxEdge = 560) {
  const scale = Math.min(1, maxEdge / Math.max(bitmap.width, bitmap.height));
  const w = Math.round(bitmap.width * scale);
  const h = Math.round(bitmap.height * scale);
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  canvas.getContext("2d").drawImage(bitmap, 0, 0, w, h);
  return new Promise((res) => {
    canvas.toBlob(
      (b) => {
        if (b && b.type === "image/webp") return res(b);
        canvas.toBlob((b2) => res(b2 || new Blob([], { type: "image/jpeg" })), "image/jpeg", 0.85);
      },
      "image/webp",
      0.82
    );
  });
}
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
        w, h,
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

/* ── Sorting / filtering ──────────────────────────────────── */
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

/* ═══════════════════════════════════════════════════════════════
   THE WORLD — three.js gallery in the void
   ═══════════════════════════════════════════════════════════════ */
const world = (() => {
  const canvas = $("#stage");
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch (err) {
    console.error(err);
    return { sync() {}, onRender() {} };
  }
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));

  const scene = new THREE.Scene();
  scene.fog = new THREE.Fog(0x0a0b0d, 900, 2600);
  const camera = new THREE.PerspectiveCamera(46, 1, 1, 8000);
  camera.position.set(0, 0, 1400);
  const group = new THREE.Group();
  scene.add(group);

  const textureLoader = new THREE.TextureLoader();
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2(-10, -10);
  let hovered = null;
  let camTargetZ = 1400;
  let camMinZ = 400;
  let camMaxZ = 3000;

  /* rotation: user drag + ambient drift */
  let rotY = 0, rotX = 0, rotVel = 0;
  let dragging = false, downX = 0, downY = 0, moved = 0, lastX = 0;

  /* ── resize ── */
  function resize() {
    const w = innerWidth, h = innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  addEventListener("resize", resize);
  resize();

  /* ── pointer interactions ── */
  canvas.style.touchAction = "none";
  canvas.addEventListener("pointerdown", (e) => {
    dragging = true;
    moved = 0;
    downX = lastX = e.clientX;
    downY = e.clientY;
    canvas.setPointerCapture(e.pointerId);
    canvas.classList.add("dragging");
  });
  canvas.addEventListener("pointermove", (e) => {
    pointer.x = (e.clientX / innerWidth) * 2 - 1;
    pointer.y = -(e.clientY / innerHeight) * 2 + 1;
    if (dragging) {
      const dx = e.clientX - lastX;
      moved += Math.abs(dx) + Math.abs(e.clientY - downY) * 0;
      lastX = e.clientX;
      rotVel = dx * 0.0032;
      rotY = THREE.MathUtils.clamp(rotY + rotVel, -0.62, 0.62);
      rotX = THREE.MathUtils.clamp(rotX + (e.clientY - downY) * 0.0006, -0.14, 0.14);
      downY = e.clientY;
    }
  });
  const endDrag = (e) => {
    if (!dragging) return;
    dragging = false;
    canvas.classList.remove("dragging");
    if (moved < 6 && e.type === "pointerup") {
      /* treat as click → raycast */
      const hit = pick();
      if (hit) openLightbox(hit.userData.rec.id);
    }
  };
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", () => { dragging = false; canvas.classList.remove("dragging"); });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    camTargetZ = THREE.MathUtils.clamp(camTargetZ + e.deltaY * 1.15, camMinZ, camMaxZ);
  }, { passive: false });

  function pick() {
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects(group.children, false);
    return hits.length ? hits[0].object : null;
  }

  /* ── layout ── */
  function layout(meshes) {
    const n = meshes.length;
    const cols = Math.max(1, Math.min(7, Math.round(Math.sqrt(n * 1.35)) || 1));
    const H = 320, GAP = 90, CELL = 420;
    const colH = new Array(cols).fill(0);
    for (const m of meshes) {
      const a = m.userData.aspect;
      let w = H * a, h = H;
      if (w > CELL) { w = CELL; h = w / a; }
      if (h > 420) { h = 420; w = h * a; }
      let c = 0;
      for (let i = 1; i < cols; i++) if (colH[i] < colH[c] - 1) c = i;
      const x = (c - (cols - 1) / 2) * (CELL + GAP);
      const y = -(colH[c] + h / 2 + GAP / 2);
      colH[c] += h + GAP;
      m.userData.tx = x;
      m.userData.ty = y;
      m.userData.tw = w;
      m.userData.th = h;
    }
    const totalH = Math.max(...colH, 0);
    const totalW = cols * (CELL + GAP) - GAP;
    for (const m of meshes) m.userData.ty += totalH / 2;
    /* fit camera */
    camTargetZ = Math.max(totalH, totalW * (innerHeight / innerWidth) * 0.9) * 0.78 + 650;
    camMinZ = 420;
    camMaxZ = Math.max(camTargetZ * 1.9, 2600);
    camTargetZ = THREE.MathUtils.clamp(camTargetZ, camMinZ, camMaxZ);
    scene.fog.near = camTargetZ * 0.45;
    scene.fog.far = camTargetZ * 2.35;
  }

  /* ── build a mesh for a record ── */
  function makeMesh(rec) {
    const aspect = rec.w / rec.h;
    const geo = new THREE.PlaneGeometry(1, 1);
    const mat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, side: THREE.DoubleSide });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.userData.rec = rec;
    mesh.userData.aspect = aspect;
    mesh.userData.born = performance.now();
    mesh.userData.lift = 0;
    mesh.userData.dim = 1;
    mesh.userData.jz = ((rec.addedAt % 1000) / 1000 - 0.5) * 130;
    mesh.userData.jr = ((rec.addedAt % 700) / 700 - 0.5) * 0.09;
    /* load texture */
    const url = thumbURL(rec);
    textureLoader.load(url, (tex) => {
      tex.colorSpace = THREE.SRGBColorSpace;
      tex.anisotropy = 4;
      mesh.material.map = tex;
      mesh.material.needsUpdate = true;
    });
    /* favorite edge */
    const edge = new THREE.LineSegments(
      new THREE.EdgesGeometry(new THREE.PlaneGeometry(1, 1)),
      new THREE.LineBasicMaterial({ color: 0x8fb0c4, transparent: true, opacity: 0 })
    );
    edge.userData.isEdge = true;
    mesh.add(edge);
    group.add(mesh);
    return mesh;
  }

  function disposeMesh(mesh) {
    group.remove(mesh);
    mesh.traverse((o) => {
      if (o.geometry) o.geometry.dispose();
      if (o.material) {
        if (o.material.map) o.material.map.dispose();
        o.material.dispose();
      }
    });
  }

  /* ── sync world with records ── */
  function sync(allItems, visItems) {
    const keep = new Set(visItems.map((r) => r.id));
    const present = new Set(allItems.map((r) => r.id));
    /* remove stale meshes */
    for (const mesh of [...group.children]) {
      if (!present.has(mesh.userData.rec.id)) disposeMesh(mesh);
    }
    /* ensure meshes for all present items */
    const byId = new Map(group.children.map((m) => [m.userData.rec.id, m]));
    for (const rec of allItems) if (!byId.has(rec.id)) makeMesh(rec);
    const meshes = [...group.children];
    /* layout in visible order */
    layout(meshes.filter((m) => keep.has(m.userData.rec.id)));
    /* dim state */
    for (const m of meshes) m.userData.dim = keep.has(m.userData.rec.id) ? 1 : 0.05;
    /* favorite edges */
    for (const m of meshes) {
      const fav = !!m.userData.rec.favorite;
      for (const child of m.children) if (child.userData.isEdge) child.userData.targetOpacity = fav ? 0.55 : 0;
    }
  }

  /* ── frame loop ── */
  let lastT = performance.now();
  function tick() {
    requestAnimationFrame(tick);
    const now = performance.now();
    const t = now / 1000;
    const dt = Math.min((now - lastT) / 1000, 0.05);
    lastT = now;

    /* inertia + ambient drift */
    if (!dragging) {
      rotY += rotVel;
      rotVel *= 0.94;
      rotY = THREE.MathUtils.clamp(rotY, -0.62, 0.62);
    }
    const ambient = REDUCED ? 0 : Math.sin(t * 0.16) * 0.016;
    group.rotation.y = rotY + ambient;
    group.rotation.x = rotX + (REDUCED ? 0 : Math.sin(t * 0.11) * 0.008);

    /* camera dolly */
    camera.position.z += (camTargetZ - camera.position.z) * 0.06;

    /* hover */
    if (!dragging && !document.body.classList.contains("ui-open")) {
      const hit = pick();
      if (hit !== hovered) {
        hovered = hit;
        canvas.style.cursor = hit ? "pointer" : "";
      }
    } else if (hovered) {
      hovered = null;
      canvas.style.cursor = "grab";
    }

    /* animate meshes */
    for (const m of group.children) {
      const d = m.userData;
      /* entrance */
      let scale = 1;
      if (!REDUCED && now - d.born < 850) {
        const p = (now - d.born) / 850;
        scale = 1 - Math.pow(1 - p, 4);
        scale = 0.001 + scale * 0.999;
      }
      /* hover lift */
      d.lift += (((hovered === m) ? 85 : 0) - d.lift) * 0.16;
      const hoverScale = (hovered === m) ? 1.045 : 1;
      /* position lerp */
      const lerp = 1 - Math.pow(0.0018, dt);
      m.position.x += (d.tx - m.position.x) * lerp;
      m.position.y += (d.ty - m.position.y) * lerp;
      m.position.z += ((d.tz || 0) + d.lift - m.position.z) * lerp;
      /* size */
      const w = d.tw || 1, h = d.th || 1;
      m.scale.set(w * scale * hoverScale, h * scale * hoverScale, 1);
      m.rotation.y = d.jr;
      /* opacity */
      const targetOp = d.dim * (hovered === m ? 1 : 0.94);
      m.material.opacity += (targetOp - m.material.opacity) * 0.14;
      /* favorite edge */
      for (const child of m.children) {
        if (child.userData.isEdge) {
          const to = child.userData.targetOpacity || 0;
          child.material.opacity += (to - child.material.opacity) * 0.12;
          child.position.z = 1;
          const s = w * 1.035;
          child.scale.set(s / w * (w / (d.tw || 1)), h * 1.035 / (d.th || 1), 1);
          child.visible = child.material.opacity > 0.02;
        }
      }
    }
    renderer.render(scene, camera);
  }
  tick();

  return {
    sync,
    group,
    refresh() { sync(state.items, visibleItems()); },
  };
})();

/* ── Rendering (DOM chrome) ────────────────────────────────── */
function render() {
  const items = state.items;
  const total = items.length;
  const bytes = items.reduce((s, r) => s + (r.size || 0), 0);

  $("#worldStats").textContent = total
    ? total + (total === 1 ? " artifact" : " artifacts") + " · " + fmtBytes(bytes) + " · local only"
    : "";

  const vis = visibleItems();
  $("#emptyState").hidden = total !== 0;
  world.sync(items, vis);

  if (state.lightboxId && !$("#lightbox").hidden) {
    if (!vis.some((r) => r.id === state.lightboxId)) closeLightbox();
  }
  updateSearchCount();
}

/* ── Search overlay ───────────────────────────────────────── */
function openSearch() {
  const ov = $("#searchOverlay");
  ov.hidden = false;
  requestAnimationFrame(() => ov.classList.add("open"));
  $("#searchInput").focus();
}
function closeSearch() {
  const ov = $("#searchOverlay");
  ov.classList.remove("open");
  setTimeout(() => { ov.hidden = true; }, 220);
  if (state.query) { state.query = ""; $("#searchInput").value = ""; render(); }
}
function updateSearchCount() {
  if (!state.query.trim()) { $("#searchCount").textContent = ""; return; }
  const vis = visibleItems().length;
  $("#searchCount").textContent = vis + (vis === 1 ? " match" : " matches");
}

/* ── Lightbox ─────────────────────────────────────────────── */
function lbList() { return visibleItems(); }
function currentRec() { return state.items.find((r) => r.id === state.lightboxId); }

function openLightbox(id) {
  state.lightboxId = id;
  $("#lightbox").hidden = false;
  requestAnimationFrame(() => $("#lightbox").classList.add("open"));
  updateLightbox();
}
function closeLightbox() {
  const lb = $("#lightbox");
  lb.classList.remove("open");
  setTimeout(() => { lb.hidden = true; }, 260);
  state.lightboxId = null;
  saveLightboxMeta();
}
function stepLightbox(dir) {
  const list = lbList();
  const i = list.findIndex((r) => r.id === state.lightboxId);
  if (i === -1 || !list.length) return;
  state.lightboxId = list[(i + dir + list.length) % list.length].id;
  updateLightbox();
}
function updateLightbox() {
  const rec = currentRec();
  if (!rec) return;
  const list = lbList();
  const i = list.findIndex((r) => r.id === rec.id);
  const img = $("#lbImage");
  const url = fullURL(rec);
  if (img.dataset.url !== url) {
    img.dataset.url = url;
    img.src = url;
  }
  img.alt = rec.name;
  $("#lbName").textContent = rec.name;
  $("#lbIndex").textContent = (i + 1) + " / " + list.length;
  $("#lbDetails").textContent = rec.w + " × " + rec.h + " · " + fmtBytes(rec.size) + " · " + fmtDate(rec.addedAt);
  $("#lbCaption").value = rec.caption || "";
  $("#lbTags").value = (rec.tags || []).join(", ");
  $("#lbFavorite").classList.toggle("active", !!rec.favorite);
  const prevRec = list[(i - 1 + list.length) % list.length];
  $("#lbImage").style.viewTransitionName = "";
  document.querySelector(".lb-stage").setAttribute("data-name", rec.name);
}
async function saveLightboxMeta() {
  const rec = currentRec();
  if (!rec) return;
  const cap = $("#lbCaption").value.trim();
  const tags = $("#lbTags").value.split(",").map((s) => s.trim()).filter(Boolean);
  const fav = $("#lbFavorite").classList.contains("active");
  if (cap !== (rec.caption || "") || JSON.stringify(tags) !== JSON.stringify(rec.tags || []) || fav !== !!rec.favorite) {
    rec.caption = cap;
    rec.tags = tags;
    rec.favorite = fav;
    await putRecord(rec);
    render();
  }
}
async function toggleFavorite() {
  const rec = currentRec();
  if (!rec) return;
  rec.favorite = !rec.favorite;
  $("#lbFavorite").classList.toggle("active", rec.favorite);
  await putRecord(rec);
  render();
}
async function deleteCurrent() {
  const rec = currentRec();
  if (!rec) return;
  await idbDelete(STORE_ITEMS, rec.id);
  dropURLs(rec.id);
  state.items = state.items.filter((r) => r.id !== rec.id);
  $("#confirmModal").hidden = true;
  toast("Removed from the vault");
  const list = lbList();
  if (list.length) { state.lightboxId = list[0].id; updateLightbox(); }
  else closeLightbox();
  render();
}

/* ── Vault locking ─────────────────────────────────────────── */
async function readCfg() {
  const row = await idbGet(STORE_META, VAULT_KEY);
  if (row && typeof row === "object") state.cfg = row;
}
async function writeCfg() {
  await idbPut(STORE_META, state.cfg, VAULT_KEY);
}
async function lockVault() {
  dropAllURLs();
  state.items = [];
  state.locked = true;
  state.key = null;
  state.query = "";
  $("#searchInput").value = "";
  $("#lightbox").hidden = true;
  $("#lightbox").classList.remove("open");
  $("#securityModal").hidden = true;
  render();
  const ls = $("#lockScreen");
  ls.hidden = false;
  requestAnimationFrame(() => ls.classList.add("open"));
  setTimeout(() => $("#unlockPass").focus(), 300);
}
async function tryUnlock(pass) {
  try {
    const salt = Uint8Array.from(atob(state.cfg.salt), (c) => c.charCodeAt(0));
    const key = await deriveKey(pass, salt);
    const ver = await decryptBuf(key, state.cfg.verifierIv, state.cfg.verifierCt);
    if (dec.decode(ver) !== "vault-ok") throw new Error();
    state.key = key;
  } catch (_) {
    $("#unlockError").hidden = false;
    setTimeout(() => { $("#unlockError").hidden = true; }, 2200);
    return;
  }
  $("#lockError")?.remove();
  const ls = $("#lockScreen");
  ls.classList.remove("open");
  setTimeout(() => { ls.hidden = true; }, 380);
  state.locked = false;
  state.items = await loadItems();
  render();
}
async function enableEncryption(newPass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(newPass, salt);
  const { iv: vIv, ct: vCt } = await encryptBuf(key, enc.encode("vault-ok"));
  state.key = key;
  state.cfg = {
    encrypted: true,
    salt: btoa(String.fromCharCode(...salt)),
    verifierIv: vIv,
    verifierCt: vCt,
  };
  for (const rec of state.items) await putRecord(rec);
  await writeCfg();
  $("#orbLock").hidden = false;
  refreshSecurityUI();
  toast("Vault encrypted — AES-256-GCM");
}
async function disableEncryption() {
  state.cfg = { encrypted: false };
  state.key = null;
  for (const rec of state.items) await putRecord(rec);
  await writeCfg();
  $("#orbLock").hidden = true;
  toast("Encryption removed — images stay local");
  refreshSecurityUI();
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

/* ── Security modal UI ────────────────────────────────────── */
function refreshSecurityUI() {
  const isOn = state.cfg.encrypted;
  const btn = $("#encToggleBtn");
  btn.textContent = isOn ? "Manage" : "Enable";
  btn.className = "btn " + (isOn ? "btn-ghost" : "btn-accent");
  $("#secStatus").textContent = isOn
    ? "On — AES-256-GCM, key in memory only"
    : "Off — images stored locally, unencrypted";
}

/* ── Wiring ───────────────────────────────────────────────── */
function closeMenu() {
  $("#menuToggle").checked = false;
}

function wire() {
  const uiOpen = () => ["#lightbox", "#securityModal", "#confirmModal", "#lockScreen"].some((s) => !$(s).hidden);
  const syncUiClass = () => document.body.classList.toggle("ui-open", uiOpen());
  const obs = new MutationObserver(syncUiClass);
  ["#lightbox", "#securityModal", "#confirmModal", "#lockScreen"].forEach((s) =>
    obs.observe($(s), { attributes: true, attributeFilter: ["hidden"] })
  );

  /* Orbital menu actions */
  $("#orbital").addEventListener("click", (e) => {
    const opt = e.target.closest(".orb-option");
    if (!opt) return;
    e.preventDefault();
    closeMenu();
    const action = opt.dataset.action;
    if (action === "add") $("#fileInput").click();
    if (action === "search") openSearch();
    if (action === "sort") cycleSort();
    if (action === "security") openModal("#securityModal");
    if (action === "lock") lockVault();
  });
  $("#menuToggle").addEventListener("change", (e) => {
    document.body.classList.toggle("menu-open", e.target.checked);
  });

  /* Sort cycling */
  function cycleSort() {
    const i = SORTS.findIndex((s) => s[0] === state.sort);
    state.sort = SORTS[(i + 1) % SORTS.length][0];
    render();
    toast("Sorted · " + SORTS.find((s) => s[0] === state.sort)[1]);
  }

  /* Modals */
  function openModal(sel) {
    const m = $(sel);
    m.hidden = false;
    requestAnimationFrame(() => m.classList.add("open"));
    refreshSecurityUI();
  }
  function closeModal(sel) {
    const m = $(sel);
    m.classList.remove("open");
    setTimeout(() => { m.hidden = true; }, 240);
  }
  document.querySelectorAll("[data-close-modal]").forEach((el) =>
    el.addEventListener("click", () => {
      closeModal("#securityModal");
      closeModal("#confirmModal");
      $("#passForm").hidden = true;
    })
  );

  /* Upload paths */
  $("#fileInput").addEventListener("change", (e) => {
    if (e.target.files.length) addFiles(e.target.files);
    e.target.value = "";
  });
  $("#emptyUploadBtn").addEventListener("click", () => $("#fileInput").click());

  /* Paste */
  window.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) addFiles(files);
  });

  /* Drag & drop */
  let dragDepth = 0;
  window.addEventListener("dragenter", (e) => {
    if (![...(e.dataTransfer?.types || [])].includes("Files")) return;
    dragDepth++;
    $("#dropOverlay").classList.add("active");
  });
  window.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) $("#dropOverlay").classList.remove("active");
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    $("#dropOverlay").classList.remove("active");
    if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
  });

  /* Search */
  $("#searchInput").addEventListener("input", (e) => {
    state.query = e.target.value;
    render();
  });
  $("#searchOverlay").addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (state.query) { state.query = ""; $("#searchInput").value = ""; render(); }
      else closeSearch();
    }
  });

  /* Lightbox */
  $("#lbClose").addEventListener("click", closeLightbox);
  $(".lb-backdrop").addEventListener("click", closeLightbox);
  $("#lbPrev").addEventListener("click", () => stepLightbox(-1));
  $("#lbNext").addEventListener("click", () => stepLightbox(1));
  $("#lbFavorite").addEventListener("click", toggleFavorite);
  $("#lbDelete").addEventListener("click", () => openModal("#confirmModal"));
  $("#confirmDeleteBtn").addEventListener("click", deleteCurrent);
  $("#lbDownload").addEventListener("click", () => {
    const rec = currentRec();
    if (!rec) return;
    const a = document.createElement("a");
    a.href = fullURL(rec);
    a.download = rec.name + "." + (rec.type.split("/")[1] || "png");
    a.click();
  });
  $("#lbCaption").addEventListener("keydown", (e) => { if (e.key === "Enter") e.target.blur(); });
  $("#lbTags").addEventListener("keydown", (e) => { if (e.key === "Enter") e.target.blur(); });

  /* Security modal */
  $("#encToggleBtn").addEventListener("click", () => {
    const form = $("#passForm");
    if (state.cfg.encrypted) {
      form.hidden = false;
      $("#passFormTitle").textContent = "Change passphrase";
      $("#curPassLabel").textContent = "Current passphrase";
      $("#newPassField").hidden = false;
      $("#newPass2Field").hidden = false;
      $("#curPass").focus();
    } else {
      form.hidden = false;
      $("#passFormTitle").textContent = "Set a passphrase";
      $("#curPassLabel").textContent = "Current passphrase";
      $("#curPass").closest(".field").hidden = true;
      $("#newPassField").hidden = false;
      $("#newPass2Field").hidden = false;
      $("#newPass").focus();
    }
  });
  $("#passForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p1 = $("#newPass").value;
    const p2 = $("#newPass2").value;
    if (state.cfg.encrypted) {
      const cur = $("#curPass").value;
      if (!cur) return toast("Enter your current passphrase");
      try {
        const salt = Uint8Array.from(atob(state.cfg.salt), (c) => c.charCodeAt(0));
        const key = await deriveKey(cur, salt);
        const ver = await decryptBuf(key, state.cfg.verifierIv, state.cfg.verifierCt);
        if (dec.decode(ver) !== "vault-ok") throw new Error();
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
      openSearch();
      return;
    }
    if (!lbOpen) {
      if (e.key === "Escape") {
        if (typing) document.activeElement.blur();
        if (!$("#searchOverlay").hidden) closeSearch();
        closeModal("#securityModal");
        closeModal("#confirmModal");
        $("#passForm").hidden = true;
      }
      return;
    }
    switch (e.key) {
      case "ArrowLeft": stepLightbox(-1); break;
      case "ArrowRight": stepLightbox(1); break;
      case "Escape": closeLightbox(); break;
      case "f": case "F": if (!typing) toggleFavorite(); break;
      case "Delete": case "Backspace": if (!typing) openModal("#confirmModal"); break;
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

  /* clicking outside the search overlay closes it */
  $("#stage").addEventListener("pointerdown", () => {
    if (!$("#searchOverlay").hidden) closeSearch();
  });
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
    $("#orbLock").hidden = false;
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

