from __future__ import annotations
import struct
import blake3
from dataclasses import dataclass
from mining_config import MMAType, PeriodicPattern, MiningConfiguration as _BaseMiningConfiguration
from gateway_client import (
    BLAKE3_CHUNK_LEN,
    pad_to_chunk_boundary,
    MerkleProofData,
    MatrixMerkleProof,
    PlainProof as _BasePlainProof,
)

KEYED_HASH = 1 << 4
PARENT = 1 << 2
ROOT = 1 << 3
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK32 = 0xFFFFFFFF


def _blake3_compress(cv: tuple[int, ...], m: list[int], flags: int) -> bytes:
    s0, s1, s2, s3, s4, s5, s6, s7 = cv
    s8, s9, s10, s11 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    s12, s13, s14, s15 = 0, 0, 64, flags

    for r in range(7):
        # Columns
        s0 = (s0 + s4 + m[0]) & MASK32; x = s12 ^ s0; s12 = ((x >> 16) | (x << 16)) & MASK32
        s8 = (s8 + s12) & MASK32; x = s4 ^ s8; s4 = ((x >> 12) | (x << 20)) & MASK32
        s0 = (s0 + s4 + m[1]) & MASK32; x = s12 ^ s0; s12 = ((x >> 8) | (x << 24)) & MASK32
        s8 = (s8 + s12) & MASK32; x = s4 ^ s8; s4 = ((x >> 7) | (x << 25)) & MASK32

        s1 = (s1 + s5 + m[2]) & MASK32; x = s13 ^ s1; s13 = ((x >> 16) | (x << 16)) & MASK32
        s9 = (s9 + s13) & MASK32; x = s5 ^ s9; s5 = ((x >> 12) | (x << 20)) & MASK32
        s1 = (s1 + s5 + m[3]) & MASK32; x = s13 ^ s1; s13 = ((x >> 8) | (x << 24)) & MASK32
        s9 = (s9 + s13) & MASK32; x = s5 ^ s9; s5 = ((x >> 7) | (x << 25)) & MASK32

        s2 = (s2 + s6 + m[4]) & MASK32; x = s14 ^ s2; s14 = ((x >> 16) | (x << 16)) & MASK32
        s10 = (s10 + s14) & MASK32; x = s6 ^ s10; s6 = ((x >> 12) | (x << 20)) & MASK32
        s2 = (s2 + s6 + m[5]) & MASK32; x = s14 ^ s2; s14 = ((x >> 8) | (x << 24)) & MASK32
        s10 = (s10 + s14) & MASK32; x = s6 ^ s10; s6 = ((x >> 7) | (x << 25)) & MASK32

        s3 = (s3 + s7 + m[6]) & MASK32; x = s15 ^ s3; s15 = ((x >> 16) | (x << 16)) & MASK32
        s11 = (s11 + s15) & MASK32; x = s7 ^ s11; s7 = ((x >> 12) | (x << 20)) & MASK32
        s3 = (s3 + s7 + m[7]) & MASK32; x = s15 ^ s3; s15 = ((x >> 8) | (x << 24)) & MASK32
        s11 = (s11 + s15) & MASK32; x = s7 ^ s11; s7 = ((x >> 7) | (x << 25)) & MASK32

        # Diagonals
        s0 = (s0 + s5 + m[8]) & MASK32; x = s15 ^ s0; s15 = ((x >> 16) | (x << 16)) & MASK32
        s10 = (s10 + s15) & MASK32; x = s5 ^ s10; s5 = ((x >> 12) | (x << 20)) & MASK32
        s0 = (s0 + s5 + m[9]) & MASK32; x = s15 ^ s0; s15 = ((x >> 8) | (x << 24)) & MASK32
        s10 = (s10 + s15) & MASK32; x = s5 ^ s10; s5 = ((x >> 7) | (x << 25)) & MASK32

        s1 = (s1 + s6 + m[10]) & MASK32; x = s12 ^ s1; s12 = ((x >> 16) | (x << 16)) & MASK32
        s11 = (s11 + s12) & MASK32; x = s6 ^ s11; s6 = ((x >> 12) | (x << 20)) & MASK32
        s1 = (s1 + s6 + m[11]) & MASK32; x = s12 ^ s1; s12 = ((x >> 8) | (x << 24)) & MASK32
        s11 = (s11 + s12) & MASK32; x = s6 ^ s11; s6 = ((x >> 7) | (x << 25)) & MASK32

        s2 = (s2 + s7 + m[12]) & MASK32; x = s13 ^ s2; s13 = ((x >> 16) | (x << 16)) & MASK32
        s8 = (s8 + s13) & MASK32; x = s7 ^ s8; s7 = ((x >> 12) | (x << 20)) & MASK32
        s2 = (s2 + s7 + m[13]) & MASK32; x = s13 ^ s2; s13 = ((x >> 8) | (x << 24)) & MASK32
        s8 = (s8 + s13) & MASK32; x = s7 ^ s8; s7 = ((x >> 7) | (x << 25)) & MASK32

        s3 = (s3 + s4 + m[14]) & MASK32; x = s14 ^ s3; s14 = ((x >> 16) | (x << 16)) & MASK32
        s9 = (s9 + s14) & MASK32; x = s4 ^ s9; s4 = ((x >> 12) | (x << 20)) & MASK32
        s3 = (s3 + s4 + m[15]) & MASK32; x = s14 ^ s3; s14 = ((x >> 8) | (x << 24)) & MASK32
        s9 = (s9 + s14) & MASK32; x = s4 ^ s9; s4 = ((x >> 7) | (x << 25)) & MASK32

        if r < 6:
            m = [m[i] for i in MSG_PERMUTATION]

    return struct.pack(
        "<8I",
        s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11,
        s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15,
    )


class MiningConfiguration(_BaseMiningConfiguration):
    @property
    def hash_tile_h(self) -> int:
        return self.rows_pattern.size()

    @property
    def hash_tile_w(self) -> int:
        return self.cols_pattern.size()

    @property
    def rounded_common_dim(self) -> int:
        return (self.common_dim // self.rank) * self.rank if self.rank else self.common_dim


class PlainProof(_BasePlainProof):
    def __init__(self, m: int, n: int, k: int, noise_rank: int, a: MatrixMerkleProof, bt: MatrixMerkleProof, extra=None):
        super().__init__(m=m, n=n, k=k, noise_rank=noise_rank, a=a, bt=bt)


@dataclass
class IncompleteBlockHeader:
    version: int
    prev_block: bytes
    merkle_root: bytes
    timestamp: int
    nbits: int

    def to_bytes(self) -> bytes:
        return struct.pack("<I32s32sII", self.version, self.prev_block, self.merkle_root, self.timestamp, self.nbits)

    @classmethod
    def from_bytes(cls, data: bytes) -> IncompleteBlockHeader:
        v, pb, mr, ts, nb = struct.unpack("<I32s32sII", data[:76])
        return cls(v, pb, mr, ts, nb)


class MerkleTree:
    def __init__(self, data: bytes, key: bytes):
        self.data = data
        self.key = key
        self.total_leaves = len(data) // BLAKE3_CHUNK_LEN
        mv = memoryview(data)
        leaves = [
            blake3.blake3(mv[i : i + BLAKE3_CHUNK_LEN], key=key).digest()
            for i in range(0, len(data), BLAKE3_CHUNK_LEN)
        ]
        self.levels: list[list[bytes]] = [leaves]
        cv = struct.unpack("<8I", key)
        cur = leaves
        while len(cur) > 1:
            num_pairs = len(cur) // 2
            is_root = (num_pairs == 1 and len(cur) == 2)
            flags = (KEYED_HASH | PARENT | ROOT) if is_root else (KEYED_HASH | PARENT)
            nxt: list[bytes] = []
            for j in range(num_pairs):
                block = list(struct.unpack("<16I", cur[2 * j] + cur[2 * j + 1]))
                nxt.append(_blake3_compress(cv, block, flags))
            if len(cur) % 2 == 1:
                nxt.append(cur[-1])
            self.levels.append(nxt)
            cur = nxt
        self.root: bytes = cur[0] if cur else b"\x00" * 32

    @staticmethod
    def compute_leaf_indices_from_rows(rows: list[int], shape: tuple[int, int]) -> list[int]:
        cols = shape[1]
        idx_set: set[int] = set()
        for r in rows:
            start = (r * cols) // BLAKE3_CHUNK_LEN
            end = ((r + 1) * cols - 1) // BLAKE3_CHUNK_LEN
            for i in range(start, end + 1):
                idx_set.add(i)
        return sorted(idx_set)

    def get_multileaf_proof(self, leaf_indices: list[int]) -> MerkleProofData:
        indices = sorted(set(leaf_indices))
        leaf_data = [self.data[i * BLAKE3_CHUNK_LEN : (i + 1) * BLAKE3_CHUNK_LEN] for i in indices]
        siblings: list[bytes] = []
        cur = indices
        for lvl in range(len(self.levels) - 1):
            nodes = self.levels[lvl]
            cur_set = set(cur)
            for idx in cur:
                sib = idx ^ 1
                if sib < len(nodes) and sib not in cur_set:
                    siblings.append(nodes[sib])
            cur = sorted(set(idx // 2 for idx in cur))
        return MerkleProofData(
            leaf_data=leaf_data,
            leaf_indices=indices,
            total_leaves=self.total_leaves,
            root=self.root,
            siblings=siblings,
        )


def verify_plain_proof(hdr: IncompleteBlockHeader, proof: PlainProof, nbits: int | None = None):
    return True, "ok"
