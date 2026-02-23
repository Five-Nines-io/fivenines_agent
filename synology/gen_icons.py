#!/usr/bin/env python3
"""Generate required PACKAGE_ICON.PNG (64x64) and PACKAGE_ICON_256.PNG (256x256) for SPK.

Synology Package Center requires these; dimensions are fixed for DSM 7.
Uses only stdlib (zlib, struct) so no extra deps. Run from synology/ or repo root.
"""
import struct
import zlib
import os


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    chunk = chunk_type + data
    return (
        struct.pack(">I", len(data))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
    )


def make_png(width: int, height: int, r: int = 40, g: int = 80, b: int = 120) -> bytes:
    raw = b""
    for _ in range(height):
        raw += b"\x00"
        raw += bytes([r, g, b]) * width
    compressed = zlib.compress(raw, 9)
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        signature
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", compressed)
        + png_chunk(b"IEND", b"")
    )


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_64 = os.path.join(script_dir, "PACKAGE_ICON.PNG")
    out_256 = os.path.join(script_dir, "PACKAGE_ICON_256.PNG")
    with open(out_64, "wb") as f:
        f.write(make_png(64, 64))
    with open(out_256, "wb") as f:
        f.write(make_png(256, 256))
    print("Generated PACKAGE_ICON.PNG (64x64) and PACKAGE_ICON_256.PNG (256x256)")


if __name__ == "__main__":
    main()
