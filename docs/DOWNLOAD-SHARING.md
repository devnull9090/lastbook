# Sharing downloads: mirrors and peers (proposal)

Status: **proposal, not built.** It needs the owner's decision, because parts of it change rules in
[SETUP-API.md](SETUP-API.md) ("Owner decisions this follows"). Nothing here is in the app.

## Why

The All library is one 388 GB zip. `downloads.lastbook.org` gives about 1.2 MB/s per connection and answers 503 once a few
connections are open (measured 2026-11-17), so even with several connections at once (engine/setup/download.py, `Segments`)
a download takes days. Many people want exactly the same bytes. Letting them get those bytes from each other, or from
mirrors run by other people, would make it much faster, but only if nobody along the way can change a byte.

## What makes it safe: piece hashes published with each file

Today each file has one SHA-256, in the manifest bundled with the app. It can only say, after the last byte, that something
somewhere in 388 GB is wrong. A source we do not control could waste days that way.

The proposal is to publish a **piece list** with each file:

- `<file>.pieces`: the SHA-256 of each 32 MiB piece, one after another (32 bytes each). For the 388 GB pack that is about
  370 KB. The pieces are the same `SEGMENT` the downloader already uses.
- In the manifest, each file entry gets
  `"pieces": {"url": "https://downloads.lastbook.org/Lastbook-All.zip.pieces", "size": 369920, "sha256": "…", "piece": 33554432}`.
  The manifest bundled with the app pins the piece list's own SHA-256, so the list cannot be swapped either. A fetched
  manifest may add a piece list only to a file the bundled manifest does not pin (the rule `manifest.merge` already applies).
- `packaging/release_manifest.py` makes the list when it publishes a file (one read of each zip).
- The downloader fetches the list first, checks its SHA-256, then checks each piece as it arrives, before counting it as
  done. It already takes the SHA-256 of every piece as it arrives (to compare with what reaches the disk), so this is one more
  comparison. A piece that does not match is thrown away, fetched again from `downloads.lastbook.org`, and the source that
  sent it is not used again in this download. The whole file's SHA-256 stays the final check.

With that in place, a source can at worst waste one piece of bandwidth. It cannot get a changed byte into a library. The piece
list also makes the repair after a failed check exact (today a zip is repaired from the CRC-32s in its central directory,
and a file that is not a zip cannot be repaired at all).

## Step 1: mirrors (small change, same rules)

- Each file entry may list `"mirrors": ["https://…"]`, used only when the file has a piece list.
- A mirror's host must be on `ALLOWED_HOSTS` and `LIBRARY_HOSTS` like any other. The owner chooses who may run one. The
  rule that the app talks only to known hosts stays, and so does `roots.pem`.
- `download.Hosts` already gives each server its own few connections and backs off one that answers 503, so each mirror adds
  its own capacity: with three mirrors a download can have three times the connections.

## Step 2: torrents, outside the app (no app change)

- Publish a BitTorrent v2 `.torrent` (SHA-256 piece hashes) for each zip, with the R2 address as a web seed (BEP 19), so a
  swarm always has a seed.
- People who want to can use qBittorrent, Transmission or `aria2c` (which also does several connections at once) and share as
  they download. Then setup's existing *Use the file you already have* checks the zip against its SHA-256 before using it.
- Nothing in the app listens, uploads or talks to peers, so none of the owner's rules change.

## Step 3: sharing from inside Lastbook (needs the owner's decision)

What it would take:

- **A listening socket and uploads.** This reverses "nothing is sent anywhere" and "the one way out" (setup's downloader is the
  only network code, and it only downloads). `test_only_module_with_connections` and the package scans would change with it.
- **Opt-in, off by default,** with a plain switch and a limit on upload speed. Only pieces that have passed their check are
  ever served.
- **Discovery.** The simplest first version is the local network only (one computer in a household, school or shelter
  downloads, and the others on the same network fetch from it). Internet-wide sharing needs a tracker or DHT and NAT
  traversal, which is BitTorrent; implementing it again is a lot of attack surface for a small team. Embedding an existing
  library (libtorrent) adds a large native dependency to every platform's package.
- **Privacy.** Peers see each other's IP addresses. A list of who downloaded a survival library is sensitive, so internet-wide
  sharing should stay something people choose outside the app (Step 2).

**Recommendation:** piece lists first (they are needed by everything else, and they improve repair on their own), then mirrors
(Step 1) and torrents (Step 2). Leave in-app sharing (Step 3) for an owner decision, starting with the local network only if it is
wanted.
