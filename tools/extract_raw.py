#!/usr/bin/env python3
"""Append only the real data chunks of an Android sparse image to a raw file.

The OS4_RODIN.zip super.img.N chunks are cumulative sparse images: each one
contains a DONT_CARE chunk covering all previously written blocks, followed by
a RAW chunk with only the new 219 MB of data. Expanding each chunk with
simg2img writes the full cumulative size (quadratic disk usage), so this
script appends only the RAW/FILL payloads.
"""
import struct
import sys

SPARSE_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: extract_raw.py <chunk.sparse> <super.img>")
    src, dst = sys.argv[1], sys.argv[2]
    appended = 0
    with open(src, "rb") as f, open(dst, "ab") as out:
        hdr = f.read(28)
        if len(hdr) != 28:
            sys.exit("short sparse header")
        magic, major, minor, fhsz, chsz, blk, total_blks, total_chunks, csum = struct.unpack(
            "<IHHHHIIII", hdr
        )
        if magic != SPARSE_MAGIC:
            sys.exit(f"bad sparse magic {magic:#x}")
        if blk <= 0:
            sys.exit("bad block size")
        for n in range(total_chunks):
            ch = f.read(12)
            if len(ch) != 12:
                sys.exit(f"short chunk header {n}")
            ctype, _, csz, ctot = struct.unpack("<HHII", ch)
            nbytes = csz * blk
            if ctype == CHUNK_TYPE_RAW:
                if ctot != 12 + nbytes:
                    sys.exit(f"bad RAW size {n}: {ctot} != {12 + nbytes}")
                left = nbytes
                while left:
                    data = f.read(min(left, 8 * 1024 * 1024))
                    if not data:
                        sys.exit(f"short RAW chunk {n}: {nbytes - left} != {nbytes}")
                    out.write(data)
                    left -= len(data)
                appended += nbytes
            elif ctype == CHUNK_TYPE_FILL:
                pat = f.read(4)
                if len(pat) != 4:
                    sys.exit(f"short FILL pattern {n}")
                block = pat * (1024 * 1024 // 4)
                left = nbytes
                while left:
                    w = min(left, len(block))
                    out.write(block[:w])
                    left -= w
                appended += nbytes
            elif ctype == CHUNK_TYPE_DONT_CARE:
                pass
            elif ctype == CHUNK_TYPE_CRC32:
                f.read(4)
            else:
                sys.exit(f"unknown chunk type {ctype:#x} at {n}")
    print(f"appended {appended} bytes from {src}")
    if appended == 0:
        sys.exit("no data appended")


if __name__ == "__main__":
    main()
