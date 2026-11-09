# VAULT — a private gallery

A local-first gallery for the random, the cursed and the legendary. No server,
no account, no analytics — every image lives in your browser's IndexedDB on
your own device and never leaves it.

## Features

- **Upload anything** — add via the menu, drag & drop anywhere on the page, or
  paste straight from the clipboard. Multiple files at once.
- **A 3D world** — your images hang as planes in a quiet void: drag to orbit,
  scroll to move, hover to lift a plane, click to open it. New arrivals scale
  in with a stagger; favorites get a thin steel edge.
- **Full viewer** — lightbox with keyboard navigation (`←` `→` `Esc`),
  favorites (`F`), delete (`Del`), editable captions and tags, download.
- **Search & sort** — instant search across names, captions and tags
  (non-matches fade into the dark); sort by newest, oldest, name or
  favorites. Press `/` to jump to search.
- **One button** — a single orbital menu fans out into Add, Search, Sort,
  Security and Lock. Almost no UI until you ask for it.
- **Optional vault encryption** — set a passphrase and every image, thumbnail,
  caption and tag is encrypted with **AES-256-GCM** before it touches storage.
  The key is derived with **PBKDF2 (600,000 iterations)** and exists only in
  memory while the vault is unlocked. Lock manually or after 10 idle minutes.
- **Backup** — export the whole archive as a decrypted JSON file and restore
  it on any device or browser.

## Security model

| Layer | Behavior |
| --- | --- |
| Storage | 100% local (IndexedDB). Zero network calls after page load. |
| Encryption (optional) | AES-256-GCM per artifact; PBKDF2-SHA256 key derivation; random salt & IV per record. |
| Key lifetime | Memory only. Never written to disk, localStorage or cookies. |
| Locking | Manual lock button + automatic lock after 10 minutes of inactivity. |

If you forget your passphrase the archive cannot be recovered — keep an export
backup.

## Tech

Vanilla HTML/CSS/JS modules, no build step, no tracking. The 3D world runs on
three.js (loaded from CDN). Type: Instrument Serif + Satoshi. Served as a
static site.

## Run locally

Just open `index.html`, or serve the folder:

```sh
npx serve .
```
