#!/usr/bin/env python3
"""Generate a DLL forwarder .def from a PE import table.

Usage:
    python tools/mkfwd.py <exe> <dll>          # emit a .def forwarding <dll>
    python tools.mkfwd.py <exe> --list         # list every imported DLL

The forwarder points at the real system copy, so the proxy DLL can be dropped
next to the game executable and still satisfy the original import.
"""

import struct
import sys


class PE:
    def __init__(self, data):
        self.d = data
        e = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e:e + 4] != b'PE\0\0':
            raise SystemExit('not a PE file')
        self.nsec = struct.unpack_from('<H', data, e + 6)[0]
        opt = e + 24
        magic = struct.unpack_from('<H', data, opt)[0]
        if magic != 0x20B:
            raise SystemExit('not x64 (magic 0x%X)' % magic)
        self.opt = opt
        self.ddir = opt + 112
        # section table: 40 bytes each, right after the optional header
        opt_size = struct.unpack_from('<H', data, e + 20)[0]
        self.sections = []
        sec = e + 24 + opt_size
        for _ in range(self.nsec):
            name = data[sec:sec + 8].rstrip(b'\0').decode('ascii', 'replace')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, sec + 8)
            chars = struct.unpack_from('<I', data, sec + 36)[0]
            self.sections.append((vaddr, vsize, rptr, rsize, name, chars))
            sec += 40

    def dir(self, index):
        rva, size = struct.unpack_from('<II', self.d, self.ddir + index * 8)
        return rva, size

    def off(self, rva):
        """RVA -> file offset."""
        for vaddr, vsize, rptr, rsize, _, _ in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rptr + (rva - vaddr)
        raise SystemExit('RVA 0x%X outside any section' % rva)

    def cstr(self, off):
        end = self.d.index(b'\0', off)
        return self.d[off:end].decode('ascii', 'replace')

    def imports(self):
        """[(dll_name, [(import_name, forward_suffix), ...]), ...]"""
        irva, _ = self.dir(1)
        if not irva:
            raise SystemExit('no import directory')
        out = []
        off = self.off(irva)
        while True:
            oft, ts, fc, name_rva, ft = struct.unpack_from('<IIIII', self.d, off)
            if not name_rva:
                break
            dll = self.cstr(self.off(name_rva))
            thunk_rva = oft or ft
            names = []
            t = self.off(thunk_rva)
            while True:
                v = struct.unpack_from('<Q', self.d, t)[0]
                if not v:
                    break
                if v & (1 << 63):                       # import by ordinal
                    names.append(('#%d' % (v & 0xFFFF), '#%d' % (v & 0xFFFF)))
                else:
                    hint = self.off(v & 0x7FFFFFFF)
                    nm = self.cstr(hint + 2)           # skip the 2-byte hint
                    names.append((nm, nm))
                t += 8
            out.append((dll, names))
            off += 20
        return out


    def exports(self):
        """[(ordinal, name, rva), ...] for the named exports, in ordinal order."""
        rva, _ = self.dir(0)
        if not rva:
            raise SystemExit('no export directory')
        ed = self.off(rva)
        fields = struct.unpack_from('<IIHHIIIIIII', self.d, ed)
        (_chars, _ts, _maj, _min, name_rva, ordinal_base, nfuncs, nnames,
         addr_funcs, addr_names, addr_ords) = fields
        out = []
        for i in range(nnames):
            nr = struct.unpack_from('<I', self.d, self.off(addr_names) + i * 4)[0]
            nm = self.cstr(self.off(nr))
            ord_ = struct.unpack_from('<H', self.d, self.off(addr_ords) + i * 2)[0]
            fr = struct.unpack_from('<I', self.d, self.off(addr_funcs) + ord_ * 4)[0]
            out.append((ordinal_base + ord_, nm, fr))
        # Sorting by ordinal makes the proxy's ordinals match the original
        # one for one, so an importer that resolves by ordinal still works.
        out.sort()
        return out

    def is_code(self, rva):
        """True when the RVA lands in an executable section."""
        for vaddr, vsize, rptr, rsize, _, chars in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return bool(chars & 0x20000000)      # IMAGE_SCN_MEM_EXECUTE
        return False

    def forwarder(self, rva):
        """The forwarder string of an export, or None when it is real code.

        A DLL can export forwarders itself; those are stored as strings in
        the export section and the function RVA points at the string.
        """
        try:
            off = self.off(rva)
        except SystemExit:
            return None
        raw = self.d[off:off + 256].split(b'\0')[0]
        try:
            txt = raw.decode('ascii')
        except UnicodeDecodeError:
            return None
        if not txt or len(txt) > 200 or ' ' in txt or '\t' in txt:
            return None
        if '.' not in txt:
            return None
        head, _, tail = txt.rpartition('.')
        if not head or not tail:
            return None
        if not head.replace('_', '').replace('-', '').replace('.', '').isalnum():
            return None
        if not tail.replace('_', '').replace('-', '').isalnum():
            return None
        return txt


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    exe = sys.argv[1]
    data = open(exe, 'rb').read()
    pe = PE(data)

    if sys.argv[2] == '--list':
        for dll, names in pe.imports():
            print('%-40s %d imports' % (dll, len(names)))
        return

    if sys.argv[2] == '--exports':
        # Forward every export of this DLL. Used when the module that
        # would import it has no import table (packed binaries), or when the
        # full export surface has to be preserved.
        #
        #   --exports <target-dll> [library-name]
        #
        # target-dll is where the forwarders point (the real library kept
        # next to the proxy), library-name is the proxy's own name.
        target = sys.argv[3].lower()
        libname = sys.argv[4] if len(sys.argv) > 4 else target.rsplit('.', 1)[0]
        print('LIBRARY %s' % libname)
        print('EXPORTS')
        count = 0
        for _ord, nm, fr in pe.exports():
            if not fr or fr & 0x80000000:      # ordinal-only export
                continue
            fwd = pe.forwarder(fr)
            if fwd:
                # The original is a forwarder DLL itself: keep its target.
                target_name = fwd
            elif pe.is_code(fr):
                target_name = '%s.%s' % (target, nm)
            else:
                continue                        # data export, cannot forward
            print('    %s = %s' % (nm, target_name))
            count += 1
        sys.stderr.write('%d forwarders\n' % count)
        return

    target = sys.argv[2].lower()
    for dll, names in pe.imports():
        if dll.lower() != target:
            continue
        print('LIBRARY %s' % dll.rsplit('.', 1)[0])
        print('EXPORTS')
        for lhs, rhs in names:
            print('    %s = %s.%s' % (lhs, dll, rhs))
        return
    raise SystemExit('%s is not imported by %s' % (target, exe))


if __name__ == '__main__':
    main()
