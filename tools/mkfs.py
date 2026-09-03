#!/usr/bin/env python3
"""cofeufs host-side writer: kernel.bin sisirilmeden disk.img'ye uygulama
(ELF) yazar. Duzel, kernelin kendi format/mount mantigini birebir taklit eder.

Kullanim: python3 tools/mkfs.py disk.img [dosya:hedef ...]
  ornek:  python3 tools/mkfs.py disk.img \\
             user/user_demo.elf:/sys/basic.cexe user/user2.elf:/sys/hello.cexe

Zaten varsa atlar (kerneldaki install idempotency'si ile ayni).
"""
import struct, sys

SB_LBA     = 2048
BM_LBA     = 2050
BM_BLOCKS  = 16
INO_LBA    = 2066
INO_BLOCKS = 64
DATA_LBA   = 2130
DISK_BLOCKS= 67584
DATA_COUNT = DISK_BLOCKS - DATA_LBA

FT_FREE, FT_FILE, FT_DIR = 0, 1, 2
INO_SIZE    = 128
INO_PER_BLK = 4
INO_COUNT   = INO_BLOCKS * INO_PER_BLK   # 256
MAX_BLOCKS  = 22
DE_SIZE     = 40
DE_PER_BLK  = 12

def inode_bytes(name, typ, size, blocks):
    b = [0xFFFFFFFF] * MAX_BLOCKS
    for k, v in enumerate(blocks):
        if k < MAX_BLOCKS:
            b[k] = v
    return struct.pack('<32sHHI22I', name.encode()[:31].ljust(31,b'\x00'), typ, 0, size, *b)

def parse_inode(buf):
    name = buf[:32].split(b'\x00')[0].decode(errors='replace')
    typ  = struct.unpack_from('<H', buf, 32)[0]
    size = struct.unpack_from('<I', buf, 36)[0]
    blocks = list(struct.unpack_from('<22I', buf, 40))
    return name, typ, size, blocks

def direntry_bytes(ino, name, typ):
    return struct.pack('<I32sB3x', ino, name.encode()[:31].ljust(31,b'\x00'), typ)

class Fs:
    def __init__(self, img):
        self.img = img
        self.bm = bytearray(BM_BLOCKS * 512)
    def read(self, lba, n=1):
        with open(self.img, 'rb') as f:
            f.seek(lba * 512); return f.read(n * 512)
    def write(self, lba, data, n=1):
        with open(self.img, 'r+b') as f:
            f.seek(lba * 512); f.write(data[:n*512]); f.flush()
    def block_set(self, i): self.bm[i >> 3] |= (1 << (i & 7))
    def block_clr(self, i): self.bm[i >> 3] &= ~(1 << (i & 7))
    def block_alloc(self):
        for i in range(DATA_COUNT):
            if not (self.bm[i >> 3] & (1 << (i & 7))):
                self.block_set(i); return i
        return None

def format(fs):
    sp = struct.pack('<8s14I', b'COFEUFS1', SB_LBA, DISK_BLOCKS-SB_LBA,
                     BM_LBA, BM_BLOCKS, INO_LBA, INO_BLOCKS, DATA_LBA,
                     DATA_COUNT, INO_PER_BLK, INO_COUNT, 0, 0, 0, 0)
    fs.write(SB_LBA, sp)
    fs.write(INO_LBA, bytearray(512*INO_BLOCKS), INO_BLOCKS)
    root = inode_bytes('/', FT_DIR, 2*DE_SIZE, [0])
    blk = bytearray(fs.read(INO_LBA)); blk[:INO_SIZE] = root
    fs.write(INO_LBA, blk)
    d0 = (direntry_bytes(0, '.', FT_DIR) + direntry_bytes(0, '..', FT_DIR)).ljust(512, b'\x00')
    fs.write(DATA_LBA + 0, d0)
    fs.block_set(0)
    fs.write(BM_LBA, bytes(fs.bm), BM_BLOCKS)
    print("mkfs: formatlandi")

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 1
    img = sys.argv[1]
    spec = sys.argv[2:]
    fs = Fs(img)

    if fs.read(SB_LBA)[:8] != b'COFEUFS1':
        format(fs)
    else:
        fs.bm = bytearray(fs.read(BM_LBA, BM_BLOCKS))

    def inode_read(n):
        blk = fs.read(INO_LBA + (n // INO_PER_BLK))
        off = (n % INO_PER_BLK) * INO_SIZE
        return bytearray(blk[off:off+INO_SIZE])
    def inode_write(n, data):
        blk = bytearray(fs.read(INO_LBA + (n // INO_PER_BLK)))
        off = (n % INO_PER_BLK) * INO_SIZE
        blk[off:off+INO_SIZE] = data
        fs.write(INO_LBA + (n // INO_PER_BLK), blk)
    def resolve(path):
        cur = 0
        for p in [x for x in path.split('/') if x]:
            name, typ, size, blocks = parse_inode(inode_read(cur))
            found = False
            for slot in range(size // DE_SIZE):
                bi = blocks[slot // DE_PER_BLK]
                if bi == 0xFFFFFFFF: break
                b = fs.read(DATA_LBA + bi)
                off = (slot % DE_PER_BLK) * DE_SIZE
                e = b[off:off+DE_SIZE]
                ino = struct.unpack_from('<I', e, 0)[0]
                nm  = e[4:36].split(b'\x00')[0].decode(errors='replace')
                if ino and nm == p:
                    cur = ino; found = True; break
            if not found: return None
        return cur
    def alloc_inode():
        for i in range(1, INO_COUNT):
            if struct.unpack_from('<H', inode_read(i), 32)[0] == FT_FREE:
                return i
        return None
    def dir_add(parent_ino, name, ino, typ):
        pn, pt, ps, pb = parse_inode(inode_read(parent_ino))
        slot = ps // DE_SIZE
        blk  = slot // DE_PER_BLK
        off  = (slot % DE_PER_BLK) * DE_SIZE
        if pb[blk] == 0xFFFFFFFF:
            bi = fs.block_alloc()
            if bi is None: return False
            pb[blk] = bi
            fs.write(DATA_LBA + bi, bytearray(512))
        b = bytearray(fs.read(DATA_LBA + pb[blk]))
        b[off:off+DE_SIZE] = direntry_bytes(ino, name, typ)
        fs.write(DATA_LBA + pb[blk], b)
        inode_write(parent_ino, inode_bytes(pn, pt, ps + DE_SIZE, pb))
        return True
    def mkdir(path):
        if resolve(path) is not None: return True
        parent = '/' + '/'.join(path.split('/')[:-1]) if path[1:].count('/') else ''
        p_ino = resolve(parent) if parent else 0
        if p_ino is None: return False
        name = path.split('/')[-1]
        ino = alloc_inode()
        if ino is None: return False
        inode_write(ino, inode_bytes(name, FT_DIR, 0, []))
        return dir_add(p_ino, name, ino, FT_DIR)
    def write_file(path, data):
        if len(data) > 22*512:
            print(f"mkfs: cok buyuk {path}"); return False
        if resolve(path) is not None: return True
        parent = '/'.join(path.split('/')[:-1])
        p_ino = resolve(parent) if parent else 0
        if p_ino is None:
            print(f"mkfs: ust dizin yok {parent}"); return False
        name = path.split('/')[-1]
        ino = alloc_inode()
        if ino is None: return False
        blocks = []
        for off in range(0, len(data), 512):
            bi = fs.block_alloc()
            if bi is None: return False
            fs.write(DATA_LBA + bi, data[off:off+512].ljust(512, b'\x00'))
            blocks.append(bi)
        inode_write(ino, inode_bytes(name, FT_FILE, len(data), blocks))
        return dir_add(p_ino, name, ino, FT_FILE)

    for d in ['temp', 'sys', 'uspc']:
        mkdir(d)

    for s in spec:
        if ':' in s:
            src, dst = s.split(':')
        else:
            src = dst = s
        data = open(src, 'rb').read()
        if write_file(dst, data):
            print(f"mkfs: + {dst} ({len(data)} bayt)")
        else:
            print(f"mkfs: atlandi/dogrulanamadi {dst}")

    fs.write(BM_LBA, bytes(fs.bm), BM_BLOCKS)
    return 0

if __name__ == '__main__':
    sys.exit(main())
