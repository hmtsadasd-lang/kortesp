#!/usr/bin/env python3
"""Copy the export ordinal base from one PE into another.

The proxy has to present the same ordinals as the DLL it shadows: Epic's
dbghelp numbers its exports from 1111, while ld always starts at 1. The
ordinal base is a single DWORD in the export directory, so the copy is a
four byte patch.

    python tools/patch_exports.py <target.dll> <source.dll>
"""

import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0].rsplit('/', 1)[0])
from mkfwd import PE


def export_dir_offset(pe):
    rva, size = pe.dir(0)
    if not rva:
        raise SystemExit('no export directory')
    return pe.off(rva), size


def named_ordinals(pe):
    """Absolute ordinals of the named exports, in export-table order."""
    off, _ = export_dir_offset(pe)
    (_c, _t, _mj, _mn, _nr, base, _nf, nnames, _af, _an, ao) = \
        struct.unpack_from('<IIHHIIIIIII', pe.d, off)
    out = []
    for i in range(nnames):
        o = struct.unpack_from('<H', pe.d, pe.off(ao) + i * 2)[0]
        out.append(base + o)
    return out


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    tgt_path, src_path = sys.argv[1], sys.argv[2]

    data = bytearray(open(tgt_path, 'rb').read())
    tgt = PE(bytes(data))
    src = PE(open(src_path, 'rb').read())

    tgt_off, _ = export_dir_offset(tgt)
    src_off, _ = export_dir_offset(src)

    tgt_base = struct.unpack_from('<I', data, tgt_off + 0x10)[0]
    src_base = struct.unpack_from('<I', src.d, src_off + 0x10)[0]

    # The proxy numbers its exports from 1, the original may start at 1111 and
    # may have unnamed exports in front of the named ones. The base has to be
    # moved so that the first *named* export lands on the original's first
    # named ordinal.
    src_named = named_ordinals(src)
    if not src_named:
        raise SystemExit('source has no named exports')
    want_base = min(src_named)

    if tgt_base == want_base:
        print('[patch] ordinal base already %d, nothing to do' % want_base)
        return

    struct.pack_into('<I', data, tgt_off + 0x10, want_base)
    open(tgt_path, 'wb').write(bytes(data))
    print('[patch] ordinal base %d -> %d (source base %d, first named ordinal %d)'
          % (tgt_base, want_base, src_base, want_base))


if __name__ == '__main__':
    main()
