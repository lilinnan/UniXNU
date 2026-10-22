#!/usr/bin/env python3
"""Set the volume UUID of a raw APFS container image (one volume), in place.

  set-apfs-volume-uuid.py IMAGE OLD_UUID NEW_UUID

The UUID is apfs_vol_uuid (offset 240) of every volume superblock object (magic APSB) whose stored Fletcher-64 checksum
is valid and holds OLD_UUID; each changed block gets its checksum recomputed. The checksum code is first checked against
every APFS object of the image, so a wrong implementation stops before anything is written.
"""
import struct
import sys
import uuid
from pathlib import Path

MOD = 0xFFFFFFFF


def fletcher64(block):
    sum1 = sum2 = 0
    for (word,) in struct.iter_unpack('<I', block[8:]):
        sum1 = (sum1 + word) % MOD
        sum2 = (sum2 + sum1) % MOD
    c1 = MOD - ((sum1 + sum2) % MOD)
    c2 = MOD - ((sum1 + c1) % MOD)
    return (c2 << 32) | c1


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    path = Path(sys.argv[1])
    old, new = uuid.UUID(sys.argv[2]).bytes, uuid.UUID(sys.argv[3]).bytes
    data = bytearray(path.read_bytes())
    if data[32:36] != b'NXSB':
        sys.exit('Not a raw APFS container (no NXSB at block 0)')
    block_size = struct.unpack_from('<I', data, 36)[0]
    if block_size not in (4096, 8192, 16384) or len(data) % block_size:
        sys.exit(f'Unexpected APFS block size {block_size}')
    checked = changed = 0
    for at in range(0, len(data), block_size):
        block = data[at:at + block_size]
        magic = bytes(block[32:36])
        if magic not in (b'NXSB', b'APSB'):
            continue
        stored = struct.unpack_from('<Q', block)[0]
        valid = fletcher64(block) == stored
        if magic == b'NXSB' and at == 0 and not valid:
            sys.exit('Checksum implementation does not reproduce the container superblock; nothing written')
        if not valid:
            continue
        checked += 1
        if magic == b'APSB' and bytes(block[240:256]) == old:
            block[240:256] = new
            struct.pack_into('<Q', block, 0, fletcher64(block))
            data[at:at + block_size] = block
            changed += 1
    if not changed:
        sys.exit(f'No valid volume superblock holds {sys.argv[2]} ({checked} valid objects checked); nothing written')
    leftover = data.count(old)
    path.write_bytes(data)
    print(f'{changed} volume superblock(s) set to {uuid.UUID(bytes=new)}; {checked} valid objects; '
          f'{leftover} other occurrence(s) of the old UUID remain')


if __name__ == '__main__':
    main()
