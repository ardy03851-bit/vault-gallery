# VAULT — a private gallery

A local-first gallery for the random, the cursed and the legendary. No server,
no account, no analytics — every image lives in your browser's IndexedDB on
your own device and never leaves it.

## Features

- **Upload anything** — click, drag & drop anywhere on the page, or paste
  straight from the clipboard. Multiple files at once.
- **Masonry archive** — a quiet, dark, museum-style grid with staggered
  entrances, hover captions and favorite markers.
- **Full viewer** — lightbox with keyboard navigation (`←` `→` `Esc`),
  favorites (`F`), delete (`Del`), editable captions and tags, download.
- **Search & sort** — instant search across names, captions and tags;
  sort by newest, oldest, name or favorites. Press `/` to jump to search.
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

Vanilla HTML/CSS/JS, no build step, no dependencies, no tracking. Served as a
static site. Type: Instrument Serif + Satoshi.

## Run locally

Just open `index.html`, or serve the folder:

```sh
npx serve .
```
