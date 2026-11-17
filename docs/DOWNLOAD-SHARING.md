# Sharing downloads: mirrors and BitTorrent

The All library is one 388 GB zip, and `downloads.lastbook.org` gives about 1.2 MB/s per connection, so a download takes days.
Many people want exactly the same bytes. This lets them get those bytes from mirrors and from each other, without anyone along
the way being able to change one.

**Owner decisions this needs.** Two parts change rules in [SETUP-API.md](SETUP-API.md) and `CONTRIBUTING.md`, and are off or
empty until the owner chooses:
- **Mirrors** are hosts that are not Lastbook's. A mirror is used only for a file whose torrent is pinned, every piece from it is
  checked, and the package scan accepts a mirror address in the bundled manifest only beside such a pin. The bundled manifest
  lists none until the owner adds some, and people can add their own in setup.
- **Sharing** runs rqbit, a BitTorrent program, which listens for peers. Lastbook itself still opens no port: it starts and stops
  rqbit. It is off unless the person turns it on, and the setting says that peers see this computer's address.

## The trust chain

1. The app's bundled manifest pins each file's SHA-256, as before. For a file with a torrent it also pins
   `torrent: {url, pieces_root, infohash_v2, piece_length}`, written by `packaging/make_torrent.py`.
2. The torrent is a hybrid BitTorrent v1 and v2 torrent of that one file, with the file's own address as its web seed. Setup
   fetches it from Lastbook's site only, and uses it only if the SHA-256 of its info is `infohash_v2` and its piece hashes add up
   to `pieces_root` (`engine/setup/torrent.py`). The info holds the v1 SHA-1 piece hashes too, so v1-only clients such as rqbit
   and aria2c check the same pinned file.
3. Each piece is then checked when it is read back from the disk (BEP 52: SHA-256 of 16 KiB blocks, built up to the piece's
   hash), whatever sent it. A mirror that sends one wrong piece is not asked again. A piece that never matches stops the download
   after a few tries, with the file kept.
4. The whole file's SHA-256 is still the last check, and a zip that fails it is repaired from the file's own address only.

So a mirror or a peer can at most waste some bandwidth. It cannot get a changed byte into a library.

A fetched manifest can never add or change a pin on a file the app was built with (`manifest.merge`). It may change that
file's `mirrors`, but only when it pins the very same file and torrent.

## Mirrors

- A file entry may list `"mirrors": ["https://…/Lastbook-All.zip", …]`: https, no user name or password, port 443, at most 16.
  They are used only when the torrent pin checks out.
- A person can add their own (Library and local AI → Mirrors, or `POST /api/setup/mirrors {add}`): the address of a copy of
  the download site's tree. The file's path on the site is added to it.
- The downloader gives each mirror its own few connections (`download.Hosts`, per host and port), as it does the file's own
  address, so each mirror adds capacity.
- TLS is checked against `roots.pem` as for every download: Let's Encrypt, Google Trust Services, Amazon and GlobalSign, which
  cover most hosts. A mirror whose certificate chains elsewhere fails and is dropped. Widening that is an owner decision.

## Sharing (seeding)

- Off by default. When the person turns it on (the choose screen, or Library and local AI → Share downloads):
  - each downloaded file with a pinned torrent is kept with its `.torrent` in `<library>.share` beside the library, instead of
    being deleted once it is unpacked. The model is shared from the library itself.
  - while Lastbook is open, `engine/setup/share.py` seeds them with rqbit:
    `rqbit --disable-dht-persistence --disable-upnp-port-forward download --overwrite --disable-http-api -o <folder> <torrents>`.
    That means no HTTP API (nothing listens for commands), no UPnP (the router is not changed) and no saved DHT state. Only
    torrents whose info matches the pin are seeded, and rqbit checks each file against its torrent before it uploads a byte.
- rqbit ends with Lastbook: through a Windows job object however Lastbook ends, through the parent-death signal on Linux, and at
  exit on a Mac.
- Turning it off stops rqbit and keeps the files. **Delete kept files** removes them. The library is never touched.
- People with a torrent client (qBittorrent, Transmission, aria2c) can download or seed the same torrent. Setup's existing
  "Use the file you already have" checks a file got that way before using it.

## For the maintainers

```bash
python3 -I -B packaging/make_torrent.py derived/release/<release>/Lastbook-All.zip --url https://downloads.lastbook.org/Lastbook-All.zip --manifest derived/release/manifest-v1.json
```

This writes `Lastbook-All.zip.torrent` (upload it beside the zip) and pins it in the packs file, which
`packaging/release_manifest.py` then bundles. The default piece length is 32 MiB, the downloader's segment, which makes about
370 KB of piece hashes for 388 GB.

```bash
python3 -I -B packaging/share/fetch_rqbit.py win-x64
```

This fetches rqbit 9.1.0 into `derived/share/`, checked against GitHub's own digests pinned in `packaging/share/rqbit.json`. The
Windows build bundles it to `_internal/share` when it is there, and the package scan accepts only that exact file. The Mac and
Linux builds do not bundle it yet, so they do not offer sharing.

## Not done yet

- Downloading from the BitTorrent swarm inside Lastbook. rqbit can stream a torrent's file with Range requests, so it could
  become one more source for the downloader. Doing that without keeping a second copy of the file needs more work.
- rqbit for the Mac and Linux packages.
- The iPad app's own downloader.
