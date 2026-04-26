from sage.all import *
import graphviz
import hashlib
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# LESS end-to-end Sage prototype (research-grade, fixed)
#
# Goals:
#   - real parameter support (LESS-252-192 by default)
#   - end-to-end keygen / sign / verify
#   - SHAKE-based sampling of generator, monomials, challenges
#   - GGM tree, GGMPath, RebuildGGM
#   - optional FAULT_ZERO_SEED inside BuildGGM
#   - easy-to-read printing helpers
#
# Design note (fix vs. original):
#   This version does NOT use a support-pattern canonicalizer. Instead, the
#   signer includes the information set J_sign it used in the withheld
#   response object, and the verifier systematizes G1 * mu_star with the same
#   J_sign. That makes the non-pivot block A deterministic in both directions
#   and removes the need for a true LESS canonical form. The `commitment` for
#   each round is then the direct byte serialization of A.
#
#   Why this matters: the previous support-pattern CF was invariant under
#   row/column permutations of its input, but the protocol needs invariance
#   under "different information-set systematizations of the same linear
#   code", which is a larger orbit. A real LESS CF (Algorithm 22/24 of the
#   spec) has that larger invariance. Forcing J_sign sidesteps the problem
#   without reimplementing it.
#
#   Consequences:
#     - response size is larger (we ship a k-subset of [0..n-1] per round)
#     - but the data flow is fully explicit, which is what we want for
#       fault-analysis research.
# ---------------------------------------------------------------------------

# ---------- Parameters ------------------------------------------------------

@dataclass
class LessParams:
    q: int
    n: int
    k: int
    t: int
    w: int
    s: int
    lambda_bits: int
    name: str = "LESS"

    @property
    def seed_bytes(self):
        return self.lambda_bits // 8

    @property
    def salt_bytes(self):
        return 2 * self.seed_bytes

    @property
    def digest_bytes(self):
        return 2 * self.seed_bytes

    @property
    def field(self):
        return GF(self.q)


LESS_252_192 = LessParams(
    q=127,
    n=252,
    k=126,
    t=192,
    w=36,
    s=2,
    lambda_bits=128,
    name="LESS-252-192",
)

# Small debug instance that runs quickly.
LESS_DEBUG = LessParams(
    q=31,
    n=12,
    k=6,
    t=8,
    w=3,
    s=2,
    lambda_bits=64,
    name="LESS-DEBUG",
)

# ---------- Hash / XOF helpers ---------------------------------------------

def shake_digest(params, data, outlen):
    if params.lambda_bits <= 128:
        return hashlib.shake_128(data).digest(outlen)
    return hashlib.shake_256(data).digest(outlen)


def sha3_digest(params, data):
    if params.digest_bytes == 32:
        return hashlib.sha3_256(data).digest()
    if params.digest_bytes == 48:
        return hashlib.sha3_384(data).digest()
    return hashlib.sha3_512(data).digest()


def le16(x):
    return int(x).to_bytes(2, "little")


def le32(x):
    return int(x).to_bytes(4, "little")


def random_bytes(n):
    import os
    return os.urandom(n)


class UniformSampler:
    """
    Byte-oriented XOF sampler. It is simpler than the paper's bit-packed
    implementation, but deterministic and uniform.
    """
    def __init__(self, params, seed):
        self.params = params
        self.seed = seed
        self.buf = b""
        self.pos = 0
        self.counter = 0

    def _refill(self, need):
        while len(self.buf) - self.pos < need:
            self.buf += shake_digest(self.params, self.seed + le32(self.counter), 64)
            self.counter += 1

    def get_u8(self):
        self._refill(1)
        x = self.buf[self.pos]
        self.pos += 1
        if self.pos > 1024:
            self.buf = self.buf[self.pos:]
            self.pos = 0
        return x

    def sample_mod(self, modulus):
        if modulus <= 0:
            raise ValueError("modulus must be positive")
        bits = (modulus - 1).bit_length()
        nbytes = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            self._refill(nbytes)
            x = int.from_bytes(self.buf[self.pos:self.pos + nbytes], "little") & mask
            self.pos += nbytes
            if x < modulus:
                return x

# ---------- Matrix serialization / printing --------------------------------

def matrix_to_entry_list(M):
    return [int(x) for row in M.rows() for x in row]


def matrix_to_bytes(M):
    vals = matrix_to_entry_list(M)
    if any(v < 0 or v > 255 for v in vals):
        raise ValueError("entry out of byte range")
    return bytes(vals)


def short_hex(b, n=16):
    h = b.hex()
    return h[:2*n] + ("..." if len(h) > 2*n else "")

# ---------- Monomial maps ---------------------------------------------------

@dataclass
class Monomial:
    pi: list   # old position -> new position
    u: list    # scalar attached to each new position


def perm_inverse(pi):
    out = [None] * len(pi)
    for old_pos, new_pos in enumerate(pi):
        out[new_pos] = old_pos
    return out


def monomial_identity(params, m=None):
    if m is None:
        m = params.n
    return Monomial(list(range(m)), [params.field(1)] * m)


def sample_monomial(params, seed, m=None):
    if m is None:
        m = params.n
    F = params.field
    rng = UniformSampler(params, seed)
    u = [F(1 + rng.sample_mod(params.q - 1)) for _ in range(m)]
    pi = list(range(m))
    for i in range(m):
        x = rng.sample_mod(m)
        pi[i], pi[x] = pi[x], pi[i]
    return Monomial(pi, u)


def monomial_inverse(params, mu):
    F = params.field
    pi_inv = perm_inverse(mu.pi)
    u_inv = [None] * len(mu.u)
    for new_pos in range(len(mu.u)):
        u_inv[new_pos] = F(1) / F(mu.u[mu.pi[new_pos]])
    return Monomial(pi_inv, u_inv)


def monomial_compose(params, mu1, mu2):
    """
    Composition mu1 o mu2, meaning apply mu2 first and then mu1.
    """
    F = params.field
    n = len(mu1.pi)
    pi1_inv = perm_inverse(mu1.pi)
    pi = [mu1.pi[old] for old in mu2.pi]
    u = [None] * n
    for new_pos in range(n):
        u[new_pos] = F(mu1.u[new_pos]) * F(mu2.u[pi1_inv[new_pos]])
    return Monomial(pi, u)


def partial_perm_from_subset(params, J, n=None):
    if n is None:
        n = params.n
    J = sorted(J)
    Jc = [i for i in range(n) if i not in set(J)]
    order = J + Jc
    pi = [None] * n
    for new_pos, old_pos in enumerate(order):
        pi[old_pos] = new_pos
    return Monomial(pi, [params.field(1)] * n)


def apply_right_monomial_to_matrix(M, mu, field):
    n = M.ncols()
    pi_inv = perm_inverse(mu.pi)
    rows = []
    for r in range(M.nrows()):
        row = []
        for new_pos in range(n):
            old_pos = pi_inv[new_pos]
            row.append(field(mu.u[new_pos]) * M[r, old_pos])
        rows.append(row)
    return matrix(field, rows)


def apply_left_monomial_to_matrix(M, mu, field):
    m = M.nrows()
    pi_inv = perm_inverse(mu.pi)
    rows = []
    for new_pos in range(m):
        old_pos = pi_inv[new_pos]
        rows.append([field(mu.u[new_pos]) * x for x in M.row(old_pos)])
    return matrix(field, rows)


def apply_monomial(params, G, mu):
    return apply_right_monomial_to_matrix(G, mu, params.field)

# ---------- Generator / challenge sampling ---------------------------------

def sample_generator(params, seed):
    F = params.field
    rng = UniformSampler(params, seed)
    rows = []
    for i in range(params.k):
        row = [F(1 if i == j else 0) for j in range(params.k)]
        row.extend(F(rng.sample_mod(params.q)) for _ in range(params.n - params.k))
        rows.append(row)
    return matrix(F, rows)


def sample_challenge(params, seed):
    rng = UniformSampler(params, seed)
    if params.s != 2:
        raise NotImplementedError("prototype currently focuses on s=2")
    ch = [0] * (params.t - params.w) + [1] * params.w
    for i in range(params.t - params.w, params.t):
        while True:
            p = rng.get_u8() % params.t
            if p <= i:
                break
        ch[i], ch[p] = ch[p], ch[i]
    return ch

# ----------------------- Graphviz -----------------------------
def _seed_hex(seed, n=8):
    return seed.hex()[:n] if seed else "None"

def visualize_ggm_graphviz(root, fault_node=None, affected_ids=None, title="GGM Tree"):
    """
    Generates a Graphviz Source object for the GGM tree.
    - fault_node: ID of the node where the fault was injected.
    - affected_ids: Set of IDs that changed due to the fault.
    """
    dot = graphviz.Digraph(comment=title)
    dot.attr(label=title, labelloc='t', fontsize='20')
    
    # Iterate through all nodes (BFS)
    q = [root]
    while q:
        node = q.pop(0)
        
        # Determine styling
        color = "white"
        style = "filled"
        label = f"ID: {node.id}\nRounds: [{node.start}..{node.end}]\nSeed: {_seed_hex(node.seed)}"
        
        if node.id == fault_node:
            color = "red" # The fault target
        elif affected_ids and node.id in affected_ids:
            color = "pink" # Propagated changes
            
        dot.node(str(node.id), label, fillcolor=color, style=style, shape="box")
        
        # Add edges and children
        if node.left:
            dot.edge(str(node.id), str(node.left.id))
            q.append(node.left)
        if node.right:
            dot.edge(str(node.id), str(node.right.id))
            q.append(node.right)
            
    return dot

def visualize_tree_diff(root_golden, root_faulted, fault_id=None):
    """
    Compares two trees and highlights nodes where seeds differ.
    """
    affected_ids = set()
    golden_map = {n.id: n for n in bfs_nodes(root_golden)}
    fault_map = {n.id: n for n in bfs_nodes(root_faulted)}
    
    for node_id, g_node in golden_map.items():
        f_node = fault_map.get(node_id)
        if f_node and g_node.seed != f_node.seed:
            affected_ids.add(node_id)
            
    return visualize_ggm_graphviz(root_faulted, fault_node=fault_id, affected_ids=affected_ids, title="Tree Diff (Correct vs Faulted)")

# ---------- Fast systematic-form data for monomial images of G0 ------------

def image_subset_of_pivots(params, mu):
    return sorted(mu.pi[:params.k])


def image_subset_from_pivot_set(pivot_set, mu):
    return sorted(mu.pi[old] for old in pivot_set)


def systematic_data_from_rref_base_and_monomial(params, G_base, pivot_set, mu):
    """
    Fast systematic-form data when the base matrix G_base is already in RREF
    with known pivot-set `pivot_set`.

    If G_base has pivot columns P and we apply a right monomial action mu,
    then the images mu(P) are still an invertible information set.
    This avoids an expensive generic information-set search.
    """
    G = apply_monomial(params, G_base, mu)
    J = image_subset_from_pivot_set(pivot_set, mu)
    Jset = set(J)
    Jc = [i for i in range(params.n) if i not in Jset]
    GJ = G.matrix_from_columns(J)
    GJc = G.matrix_from_columns(Jc)
    A = GJ.inverse() * GJc
    pi_tilde = partial_perm_from_subset(params, J, params.n)
    systematic = GJ.inverse() * G
    systematic = systematic.matrix_from_columns(J + Jc)
    return {
        "G": G,
        "J": J,
        "Jc": Jc,
        "A": A,
        "pi_tilde": pi_tilde,
        "systematic": systematic,
    }


def systematic_data_from_monomial_image(params, G0, mu):
    """
    Since G0 is systematic [I_k | A], after a monomial action the images of the
    original pivot columns still form an invertible information set.
    """
    return systematic_data_from_rref_base_and_monomial(
        params, G0, list(range(params.k)), mu
    )


def systematic_data_with_forced_J(params, G_base, mu, J_forced):
    """
    Apply monomial mu to G_base (right action), then systematize using the
    caller-supplied information set J_forced instead of deriving one.

    Used by the fixed verifier: the signer tells the verifier which J to use,
    so both sides compute the same non-pivot block A.

    Requires J_forced to be a valid info-set (columns at J_forced form an
    invertible k x k submatrix). If it isn't, raises a ValueError — which
    is useful as a bug detector.
    """
    G = apply_monomial(params, G_base, mu)
    J = sorted(int(x) for x in J_forced)
    Jset = set(J)
    Jc = [i for i in range(params.n) if i not in Jset]
    GJ = G.matrix_from_columns(J)
    if GJ.rank() != params.k:
        raise ValueError(
            "systematic_data_with_forced_J: J is not a valid info-set "
            "(rank %d, expected %d)" % (GJ.rank(), params.k)
        )
    GJc = G.matrix_from_columns(Jc)
    A = GJ.inverse() * GJc
    systematic = GJ.inverse() * G
    systematic = systematic.matrix_from_columns(J + Jc)
    return {
        "G": G,
        "J": J,
        "Jc": Jc,
        "A": A,
        "systematic": systematic,
    }

# ---------- Canonical form (prototype support-pattern canonicalizer) --------

def canonicalize_zero_pattern(A):
    """
    DEPRECATED for the fixed prototype. Kept only so old callers don't crash
    if imported. See the design note at the top of this file — the fixed
    model does not canonicalize, it commits to A directly after forcing a
    shared information set J_sign on signer and verifier.
    """
    B = [[0 if int(x) == 0 else 1 for x in row] for row in A.rows()]
    changed = True
    while changed:
        changed = False
        new_rows = sorted(B)
        if new_rows != B:
            B = new_rows
            changed = True
        cols = list(zip(*B)) if B and B[0] else []
        new_cols = sorted(cols)
        if new_cols != cols:
            B = [list(row) for row in zip(*new_cols)]
            changed = True
    return B


def commit_matrix_bytes(params, A):
    """
    Byte-serialize the non-pivot block A of a systematic form [I | A].
    This replaces the old cf_prototype + cf_to_bytes pair.

    `A` is a k x (n-k) matrix over F_q; we serialize as q in little-endian
    bytes per entry. For q < 256 that is one byte per entry; for larger q
    we use ceil(log_256 q) bytes.
    """
    q = params.q
    byte_len = max(1, (q.bit_length() + 7) // 8)
    out = bytearray()
    for r in range(A.nrows()):
        for c in range(A.ncols()):
            v = int(A[r, c]) % q
            out.extend(int(v).to_bytes(byte_len, "little"))
    return bytes(out)


def cf_prototype(params, A):
    # Kept for callers that might still invoke it; returns the A matrix
    # unchanged (no canonicalization). The actual "CF" of the fixed
    # protocol is handled by commit_matrix_bytes.
    return A


def cf_to_bytes(cf_obj):
    # Compatibility shim. If callers pass a matrix, serialize it directly.
    if hasattr(cf_obj, "nrows"):
        # We lost params here; assume q fits in one byte. Real call sites
        # should use commit_matrix_bytes(params, A) directly.
        out = bytearray()
        for r in range(cf_obj.nrows()):
            for c in range(cf_obj.ncols()):
                out.append(int(cf_obj[r, c]) & 0xFF)
        return bytes(out)
    flat = [x for row in cf_obj for x in row]
    return bytes(flat)

# ---------- Blinding --------------------------------------------------------

def blind_matrix(params, A, state_seed):
    left = sample_monomial(params, state_seed + b"|blindL|", m=params.k)
    right = sample_monomial(params, state_seed + b"|blindR|", m=params.n - params.k)
    B = apply_left_monomial_to_matrix(A, left, params.field)
    C = apply_right_monomial_to_matrix(B, right, params.field)
    return C

# ---------- GGM tree --------------------------------------------------------

@dataclass
class GGMNode:
    id: int
    start: int
    end: int
    seed: object = None
    left: object = None
    right: object = None
    parent: object = None

    @property
    def size(self):
        return self.end - self.start + 1

    def is_leaf(self):
        return self.left is None and self.right is None


def decompose_t(total):
    parts = []
    cur = 0
    bit = 1 << (total.bit_length() - 1)
    rem = total
    while bit:
        if rem & bit:
            parts.append((bit, cur, cur + bit - 1))
            cur += bit
        bit >>= 1
    return parts


def build_structure(params):
    next_id = [0]
    def new_id():
        x = next_id[0]
        next_id[0] += 1
        return x

    def perfect(size, lo, hi, parent=None):
        node = GGMNode(new_id(), lo, hi, parent=parent)
        if size == 1:
            return node
        half = size // 2
        node.left = perfect(half, lo, lo + half - 1, node)
        node.right = perfect(half, lo + half, hi, node)
        return node

    parts = decompose_t(params.t)
    if len(parts) == 1:
        size, lo, hi = parts[0]
        return perfect(size, lo, hi)

    root = GGMNode(new_id(), 0, params.t - 1)
    first = parts[0]
    root.left = perfect(first[0], first[1], first[2], root)
    if len(parts) == 2:
        second = parts[1]
        root.right = perfect(second[0], second[1], second[2], root)
    else:
        def merged(rem_parts, parent=None):
            node = GGMNode(new_id(), rem_parts[0][1], rem_parts[-1][2], parent=parent)
            first = rem_parts[0]
            node.left = perfect(first[0], first[1], first[2], node)
            if len(rem_parts) == 2:
                second = rem_parts[1]
                node.right = perfect(second[0], second[1], second[2], node)
            else:
                node.right = merged(rem_parts[1:], node)
            return node
        root.right = merged(parts[1:], root)
    return root


def bfs_nodes(root):
    out = []
    q = [root]
    while q:
        x = q.pop(0)
        out.append(x)
        if x.left is not None:
            q.append(x.left)
        if x.right is not None:
            q.append(x.right)
    return out


def leaf_nodes(root):
    return [x for x in bfs_nodes(root) if x.is_leaf()]


def build_ggm(params, seedtree, salt, fault_zero_seed_node=None):
    root = build_structure(params)
    root.seed = seedtree
    q = [root]
    while q:
        node = q.pop(0)
        if node.is_leaf():
            continue
        seed_here = node.seed
        if fault_zero_seed_node is not None and node.id == fault_zero_seed_node:
            seed_here = b"\x00" * params.seed_bytes
            node.seed = seed_here
        stream = shake_digest(params, seed_here + salt + le16(node.id), 2 * params.seed_bytes)
        left_seed = stream[:params.seed_bytes]
        right_seed = stream[params.seed_bytes:]
        node.left.seed = left_seed
        node.right.seed = right_seed
        q.append(node.left)
        q.append(node.right)
    leaves = sorted(leaf_nodes(root), key=lambda z: z.start)
    return root, [x.seed for x in leaves]


def compute_publish_stencil(root, U):
    U = set(U)
    marked = {}
    def rec(node):
        if node.is_leaf():
            marked[node.id] = (node.start not in U)
            return marked[node.id]
        left_ok = rec(node.left)
        right_ok = rec(node.right)
        marked[node.id] = left_ok and right_ok
        return marked[node.id]
    rec(root)
    return marked


def ggm_path(params, seedtree, salt, U, fault_zero_seed_node=None):
    root, _ = build_ggm(params, seedtree, salt, fault_zero_seed_node=fault_zero_seed_node)
    marked = compute_publish_stencil(root, U)
    path = []
    for node in bfs_nodes(root):
        parent_mark = False if node.parent is None else marked[node.parent.id]
        if marked[node.id] and not parent_mark:
            path.append(node.seed)
    return path


def rebuild_ggm(params, path, salt, U):
    root = build_structure(params)
    marked = compute_publish_stencil(root, U)
    Uset = set(U)

    def expand_seeded_subtree(node):
        q = [node]
        while q:
            cur = q.pop(0)
            if cur.is_leaf():
                continue
            if cur.seed is None:
                raise ValueError("seeded subtree expansion reached a node without seed")
            stream = shake_digest(params, cur.seed + salt + le16(cur.id), 2 * params.seed_bytes)
            cur.left.seed = stream[:params.seed_bytes]
            cur.right.seed = stream[params.seed_bytes:]
            q.append(cur.left)
            q.append(cur.right)

    # Walk the tree in BFS order — the SAME order ggm_path() used to emit
    # the path. For every maximal-published subtree root, consume one entry
    # from path, assign it as the seed, and expand the subtree to fill
    # in descendant seeds. For nodes not at such a root, just descend.
    #
    # Previously this function used a pre-order recursion, which consumes
    # the path in DFS order. Since ggm_path emits BFS, the two disagreed
    # whenever the tree was not structured so that BFS == pre-order DFS
    # (i.e. almost always), and every published round got the wrong seed.
    path_idx = 0
    for node in bfs_nodes(root):
        parent_mark = False if node.parent is None else marked[node.parent.id]
        if marked[node.id] and not parent_mark:
            if path_idx >= len(path):
                raise ValueError("path ended too early while rebuilding GGM")
            node.seed = path[path_idx]
            path_idx += 1
            expand_seeded_subtree(node)

    if path_idx != len(path):
        raise ValueError("unused nodes remain in path after GGM rebuild")

    leaves = sorted(leaf_nodes(root), key=lambda z: z.start)
    out = {}
    for leaf in leaves:
        if leaf.start not in Uset:
            if leaf.seed is None:
                raise ValueError("missing rebuilt seed for round %d" % leaf.start)
            out[leaf.start] = leaf.seed
    return out

# ---------- Explicit withheld responses (research model) --------------------

def monomial_to_bytes(params, mu):
    out = bytearray()
    for x in mu.pi:
        out.extend(int(x).to_bytes(2, 'little'))
    for x in mu.u:
        out.append(int(x))
    return bytes(out)


def monomial_from_bytes(params, blob):
    n = params.n
    need = 2 * n + n
    if len(blob) != need:
        raise ValueError("bad monomial blob length")
    pi = []
    off = 0
    for _ in range(n):
        pi.append(int.from_bytes(blob[off:off+2], 'little'))
        off += 2
    u = [params.field(b) for b in blob[off:off+n]]
    return Monomial(pi, u)


def explicit_rsp_from_monomial(params, mu_star, J_sign):
    """
    Research-grade response object:
      return the full monomial µ* = π_tilde ∘ µ_e ∘ τ_1 AND the signer's
      information set J_sign.

    J_sign is the k-subset of {0,...,n-1} that the signer used to systematize
    G0 * mu_e. The verifier re-uses it to systematize G1 * mu_star, which
    forces signer and verifier to produce the same non-pivot block A.

    This is *not* the compressed production LESS response (which ships
    the coset rep and relies on a real CF to agree across info-set choices).
    For fault analysis we want an explicit object that can be inspected,
    serialized, and algebraically combined with known π_tilde values.
    """
    return {
        "pi": tuple(int(x) for x in mu_star.pi),
        "u": tuple(int(x) for x in mu_star.u),
        "J": tuple(sorted(int(x) for x in J_sign)),   # signer's info-set
        "blob": monomial_to_bytes(params, mu_star),
    }


def explicit_rsp_to_monomial(params, rsp_obj):
    return Monomial(list(rsp_obj["pi"]), [params.field(x) for x in rsp_obj["u"]])


def explicit_rsp_get_J(rsp_obj):
    return list(rsp_obj["J"])


# ---------- Keygen / sign / verify -----------------------------------------


def _selfcheck_explicit_rsp_round(params, G_pub, pivot_set_pub, rsp_obj, A_expected_bytes):
    """
    Debug helper for the research model:
      rebuild A from the *explicit* withheld-round monomial response and
      compare the byte serialization of A against what the signer committed.

    The systematization on the verifier side uses info-set {0..k-1} on
    G1 * mu_star; see verify() for the algebra. Returns True iff the
    verifier would accept this round.

    `pivot_set_pub` is accepted for API compatibility but not used — the
    fixed protocol derives the info-set purely from the mu_star permutation.
    """
    del pivot_set_pub  # unused in the fixed protocol
    mu_star = explicit_rsp_to_monomial(params, rsp_obj)
    try:
        sys = systematic_data_with_forced_J(
            params, G_pub, mu_star, list(range(params.k))
        )
    except ValueError:
        return False
    return commit_matrix_bytes(params, sys["A"]) == A_expected_bytes

def keygen(params, seedsk=None):
    #if seedsk is None:
    #    seedsk = random_bytes(params.seed_bytes)
    state0 = shake_digest(params, seedsk + b"|statesk|", 4 * params.seed_bytes)
    seedpk = state0[:params.seed_bytes]
    seed1 = state0[params.seed_bytes:2 * params.seed_bytes]

    G0 = sample_generator(params, seedpk)
    tau1 = sample_monomial(params, seed1)
    mu1 = monomial_inverse(params, tau1)

    # LESS public key component:
    #   G1 = RREF(mu1(G0))
    #
    # Important: this is *not* the same as storing a particular systematic
    # form tied to one chosen information set. Using a systematicized version
    # here breaks every withheld-round response at once, because verify() uses
    # rsp to select an information set inside the public-key matrix G1.
    G1_raw = apply_monomial(params, G0, mu1)
    G1 = G1_raw.echelon_form()

    sk = {
        "seedsk": seedsk,
    }
    piv1 = list(G1.pivots())
    pk = {
        "seedpk": seedpk,
        "G1": G1,
        "piv1": piv1,
    }
    aux = {
        "G0": G0,
        "tau1": tau1,
        "mu1": mu1,
        "piv1": piv1,
    }
    return sk, pk, aux


def sign(params, sk, msg, salt=None, fault_zero_seed_node=None, verbose=False):
    seedsk = sk["seedsk"]
    sk2, pk, aux = keygen(params, seedsk)
    G0 = aux["G0"]
    tau1 = aux["tau1"]

    #if salt is None:
    #    salt = random_bytes(params.salt_bytes)
    seedtree = shake_digest(params, seedsk + b"|seedtree|", params.seed_bytes)
    blind_root = shake_digest(params, seedsk + b"|blind-root|", params.seed_bytes)

    tree_root, round_seeds = build_ggm(
        params,
        seedtree,
        salt,
        fault_zero_seed_node=fault_zero_seed_node,
    )

    round_data = []
    commitments = []
    for i in range(params.t):
        mu_e_seed = round_seeds[i] + salt + msg + le16(i)
        mu_e = sample_monomial(params, mu_e_seed)
        sys = systematic_data_from_monomial_image(params, G0, mu_e)
        # Fixed-model commitment: no blinding, no CF — commit directly to the
        # bytes of the non-pivot block A. Both the signer (here) and the
        # verifier (below) use the SAME information set J_sign, so the matrix
        # A is bit-exact on both sides.
        A_bytes = commit_matrix_bytes(params, sys["A"])
        commitments.append(A_bytes)
        round_data.append({
            "mu_e": mu_e,
            "J": sys["J"],
            "A": sys["A"],
            "A_bytes": A_bytes,
            "pi_tilde": sys["pi_tilde"],
        })

    cmt = sha3_digest(params, b"".join(commitments) + salt + msg)
    ch = sample_challenge(params, cmt)
    U = [i for i, x in enumerate(ch) if x != 0]

    path = ggm_path(
        params,
        seedtree,
        salt,
        U,
        fault_zero_seed_node=fault_zero_seed_node,
    )

    withheld = {}
    for i in U:
        mu_star = monomial_compose(
            params,
            monomial_compose(params, round_data[i]["pi_tilde"], round_data[i]["mu_e"]),
            tau1,
        )
        withheld[i] = explicit_rsp_from_monomial(
            params, mu_star, round_data[i]["J"]
        )
        if verbose:
            ok_rsp = _selfcheck_explicit_rsp_round(
                params, pk["G1"], pk["piv1"], withheld[i], round_data[i]["A_bytes"]
            )
            if not ok_rsp:
                print("sign: explicit rsp self-check failed at round", i)

    sig = {
        "cmt": cmt,
        "salt": salt,
        "path": path,
        "withheld": withheld,
        "challenge": ch,
        "U": U,
        "tree_root": tree_root,
        "round_seeds": round_seeds,
        "fault_zero_seed_node": fault_zero_seed_node,
        "withheld_model": "explicit_monomial",
    }
    if verbose:
        print("sign: challenge weight =", sum(ch))
        print("sign: withheld rounds U =", U)
        print("sign: path nodes =", len(path))
        print("sign: cmt =", short_hex(cmt, 16))
    return sig, tree_root, round_seeds


def verify(params, pk, msg, sig, verbose=False):
    seedpk = pk["seedpk"]
    G0 = sample_generator(params, seedpk)
    G1 = pk["G1"]
    piv1 = pk["piv1"]

    cmt = sig["cmt"]
    salt = sig["salt"]
    ch = sample_challenge(params, cmt)
    U = [i for i, x in enumerate(ch) if x != 0]

    if sorted(U) != sorted(sig["U"]):
        if verbose:
            print("verify: U mismatch")
        return False

    for i, rsp_obj in sig["withheld"].items():
        if len(rsp_obj["pi"]) != params.n or len(rsp_obj["u"]) != params.n:
            if verbose:
                print("verify: bad explicit rsp at round", i)
            return False

    rebuilt = rebuild_ggm(params, sig["path"], salt, U)

    commitments = []
    for i in range(params.t):
        if ch[i] == 0:
            if i not in rebuilt:
                raise ValueError("rebuild_ggm did not recover round seed %d" % i)
            mu_e_seed = rebuilt[i] + salt + msg + le16(i)
            mu_e = sample_monomial(params, mu_e_seed)
            # Published round: same info-set derivation as sign() — the image
            # of [0..k-1] under mu_e, which comes out of
            # systematic_data_from_monomial_image. No choice issue here.
            sys = systematic_data_from_monomial_image(params, G0, mu_e)
            A_bytes = commit_matrix_bytes(params, sys["A"])
        else:
            # Withheld round. Algebra (derived in PROTOTYPE_BUG_ANALYSIS.md):
            #   mu_star = compose(compose(pi_tilde, mu_e), tau1)
            #   G1 * mu_star = R * G0 * mu_e * pi_tilde
            #   where pi_tilde maps J_sign -> {0..k-1}.
            # So G_full = G1 * mu_star has its FIRST k columns corresponding
            # to J_sign of G0*mu_e. Systematizing G_full with info-set
            # {0..k-1} therefore reproduces A_sign exactly (the row op R
            # cancels because we left-multiply by the inverse of the info-
            # set block).
            mu_star = explicit_rsp_to_monomial(params, sig["withheld"][i])
            J_sign = explicit_rsp_get_J(sig["withheld"][i])
            try:
                sys = systematic_data_with_forced_J(
                    params, G1, mu_star, list(range(params.k))
                )
            except ValueError as e:
                if verbose:
                    print("verify: bad permuted info-set at round %d: %s" % (i, e))
                return False
            # Optional sanity check: verify J_sign is consistent with the
            # mu_star we received. pi_tilde embedded in mu_star should map
            # J_sign -> {0..k-1}, i.e. mu_star.pi restricted to J_sign
            # should be a permutation of {0..k-1} when composed with tau1's
            # effect. We don't know tau1 here (secret), so we check a
            # weaker invariant: J_sign has size k and all entries in range.
            if len(J_sign) != params.k or any(j < 0 or j >= params.n for j in J_sign):
                if verbose:
                    print("verify: malformed J_sign at round %d" % i)
                return False
            A_bytes = commit_matrix_bytes(params, sys["A"])
        commitments.append(A_bytes)

    cmt2 = sha3_digest(params, b"".join(commitments) + salt + msg)
    ok = (cmt == cmt2)
    if verbose:
        print("verify: recomputed cmt =", short_hex(cmt2, 16))
        print("verify:", ok)
    return ok

# ---------- Tree / round inspection ----------------------------------------

def find_node(root, node_id):
    for node in bfs_nodes(root):
        if node.id == node_id:
            return node
    return None


def descendant_rounds(root, node_id):
    node = find_node(root, node_id)
    if node is None:
        return []
    return list(range(node.start, node.end + 1))


def print_tree_summary(root, max_nodes=60):
    nodes = bfs_nodes(root)
    print("tree summary (first %d BFS nodes)" % min(max_nodes, len(nodes)))
    for node in nodes[:max_nodes]:
        tag = "leaf" if node.is_leaf() else "node"
        parent = None if node.parent is None else node.parent.id
        print(
            "  %s id=%d parent=%s rounds=[%d..%d] size=%d seed=%s" % (
                tag,
                node.id,
                parent,
                node.start,
                node.end,
                node.size,
                short_hex(node.seed if node.seed is not None else b"", 8),
            )
        )


# ---------- Tree visualization ---------------------------------------------

def _seed_short(seed, n=8):
    if seed is None:
        return "????????"
    h = seed.hex()
    return h[:n]


def _collect_subtree_ids(node):
    """All node IDs reachable from `node` (inclusive)."""
    out = set()
    q = [node]
    while q:
        cur = q.pop(0)
        out.add(cur.id)
        if cur.left is not None:
            q.append(cur.left)
        if cur.right is not None:
            q.append(cur.right)
    return out


def _ancestors_of(node):
    """All ancestor IDs of `node` (not including node itself)."""
    out = []
    cur = node.parent
    while cur is not None:
        out.append(cur.id)
        cur = cur.parent
    return out


def print_tree_ascii(root,
                     max_depth=4,
                     fault_node=None,
                     highlight_ids=None,
                     hide_leaf_seeds=False,
                     title="GGM tree"):
    """
    Render the GGM tree as ASCII. Shows:
      - tree structure with ├── / └── connectors
      - each node: id, round range, size, 8-hex of seed
      - annotations:
          * [F]  = this node is the fault target
          * [D]  = this node is a descendant of the fault target (in D(v))
          * [A]  = this node is an ancestor of the fault target
          * [*]  = this node is in the caller-provided highlight set

    Parameters
    ----------
    root        : GGMNode, the tree root
    max_depth   : int, how many levels to descend from the root (inclusive)
    fault_node  : int or None, node id flagged as the fault target
    highlight_ids : set of ints, extra ids to mark with [*]
    hide_leaf_seeds : if True, don't print seed bytes for leaves (the usual
                      case when the tree was built WITHOUT the seeds being
                      materialized — e.g. in verify() where only some leaves
                      are rebuilt)
    title       : header line
    """
    highlight_ids = set(highlight_ids) if highlight_ids else set()

    # Precompute annotations
    fault_obj = None
    D_ids = set()
    A_ids = set()
    if fault_node is not None:
        for node in bfs_nodes(root):
            if node.id == fault_node:
                fault_obj = node
                break
        if fault_obj is not None:
            D_ids = _collect_subtree_ids(fault_obj) - {fault_obj.id}
            A_ids = set(_ancestors_of(fault_obj))

    print("-" * 78)
    print(title)
    if fault_node is not None:
        print("  legend: [F] fault target  [D] descendant of F  [A] ancestor of F")
    if highlight_ids:
        print("  legend: [*] highlighted node")
    print("-" * 78)

    def label(node):
        tag = "leaf" if node.is_leaf() else "node"
        marks = []
        if fault_node is not None and node.id == fault_node:
            marks.append("[F]")
        elif node.id in D_ids:
            marks.append("[D]")
        elif node.id in A_ids:
            marks.append("[A]")
        if node.id in highlight_ids:
            marks.append("[*]")
        mark = " ".join(marks)
        if mark:
            mark = " " + mark
        seed_s = "----"
        if node.seed is not None and not (hide_leaf_seeds and node.is_leaf()):
            seed_s = _seed_short(node.seed, 8)
        return "%s id=%d rounds=[%d..%d] size=%d seed=%s%s" % (
            tag, node.id, node.start, node.end, node.size, seed_s, mark
        )

    def rec(node, prefix, is_last, depth):
        connector = "└── " if is_last else "├── "
        print(prefix + connector + label(node))
        if node.is_leaf() or depth >= max_depth:
            if not node.is_leaf() and depth >= max_depth:
                # Show a count of elided descendants so the reader knows
                # the tree continues below.
                sub = _collect_subtree_ids(node) - {node.id}
                child_prefix = prefix + ("    " if is_last else "│   ")
                print(child_prefix + "... (%d more descendant nodes hidden)" % len(sub))
            return
        children = []
        if node.left is not None:
            children.append(node.left)
        if node.right is not None:
            children.append(node.right)
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, ch in enumerate(children):
            rec(ch, child_prefix, i == len(children) - 1, depth + 1)

    rec(root, "", True, 0)


def print_subtree(root, node_id, max_depth=3, fault_node=None, title=None):
    """Zoom in: render a subtree rooted at `node_id`."""
    target = None
    for n in bfs_nodes(root):
        if n.id == node_id:
            target = n
            break
    if target is None:
        print("print_subtree: node id %d not found" % node_id)
        return
    hdr = title if title else ("subtree rooted at id=%d (rounds [%d..%d])"
                                % (target.id, target.start, target.end))
    print_tree_ascii(target, max_depth=max_depth, fault_node=fault_node,
                     title=hdr)


def print_tree_diff(root_golden, root_faulted,
                    fault_node,
                    max_depth=4,
                    title="tree diff: golden vs faulted"):
    """
    Show golden vs faulted side by side, marking:
      - [F] fault target
      - [D] descendant of fault target (in D(v))
      - [!] seed changed between golden and faulted
      - [=] seed unchanged

    The tree shape is identical between the two trees (same build_structure
    output), so we walk one and look up the other by id.
    """
    # Build id -> node map for faulted tree
    fault_map = {n.id: n for n in bfs_nodes(root_faulted)}

    # Precompute D_ids from golden (same shape, same ids)
    fault_obj = None
    for n in bfs_nodes(root_golden):
        if n.id == fault_node:
            fault_obj = n
            break
    D_ids = set()
    A_ids = set()
    if fault_obj is not None:
        D_ids = _collect_subtree_ids(fault_obj) - {fault_obj.id}
        A_ids = set(_ancestors_of(fault_obj))

    # Count changed seeds
    n_changed = 0
    n_total = 0
    for n in bfs_nodes(root_golden):
        fn = fault_map.get(n.id)
        if fn is None:
            continue
        n_total += 1
        if n.seed != fn.seed:
            n_changed += 1

    print("-" * 78)
    print(title)
    print("  legend: [F] fault target  [D] descendant  [A] ancestor  "
          "[!] seed changed  [=] seed unchanged")
    print("  seeds changed: %d / %d nodes" % (n_changed, n_total))
    print("-" * 78)

    def label(g_node, f_node):
        tag = "leaf" if g_node.is_leaf() else "node"
        marks = []
        if g_node.id == fault_node:
            marks.append("[F]")
        elif g_node.id in D_ids:
            marks.append("[D]")
        elif g_node.id in A_ids:
            marks.append("[A]")
        if f_node is None:
            marks.append("[missing]")
            mark_str = " ".join(marks)
            return "%s id=%d rounds=[%d..%d] g=%s%s" % (
                tag, g_node.id, g_node.start, g_node.end,
                _seed_short(g_node.seed, 8),
                (" " + mark_str) if mark_str else "")
        changed = (g_node.seed != f_node.seed)
        marks.append("[!]" if changed else "[=]")
        mark_str = " ".join(marks)
        return "%s id=%d rounds=[%d..%d] g=%s f=%s %s" % (
            tag, g_node.id, g_node.start, g_node.end,
            _seed_short(g_node.seed, 8),
            _seed_short(f_node.seed, 8),
            mark_str,
        )

    def rec(g_node, prefix, is_last, depth):
        connector = "└── " if is_last else "├── "
        f_node = fault_map.get(g_node.id)
        print(prefix + connector + label(g_node, f_node))
        if g_node.is_leaf() or depth >= max_depth:
            if not g_node.is_leaf() and depth >= max_depth:
                sub = _collect_subtree_ids(g_node) - {g_node.id}
                child_prefix = prefix + ("    " if is_last else "│   ")
                print(child_prefix + "... (%d more descendant nodes hidden)" % len(sub))
            return
        children = []
        if g_node.left is not None:
            children.append(g_node.left)
        if g_node.right is not None:
            children.append(g_node.right)
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, ch in enumerate(children):
            rec(ch, child_prefix, i == len(children) - 1, depth + 1)

    rec(root_golden, "", True, 0)


def print_changed_leaves(root_golden, root_faulted, fault_node):
    """
    One-line per leaf showing golden-vs-faulted seed and whether the
    round is in D(v). Compact summary for the paper.
    """
    fault_map = {n.id: n for n in bfs_nodes(root_faulted)}
    fault_obj = None
    for n in bfs_nodes(root_golden):
        if n.id == fault_node:
            fault_obj = n
            break
    D_ids = set()
    if fault_obj is not None:
        D_ids = _collect_subtree_ids(fault_obj)

    print("-" * 78)
    print("leaf seeds: golden vs faulted (fault at id=%s)" % fault_node)
    print("  legend: [D] leaf in D(v)   [!] seed differs")
    print("-" * 78)
    print("  %-7s %-7s %-20s %-20s  %s" %
          ("round", "leaf_id", "golden_seed", "faulted_seed", "marks"))

    leaves_g = sorted(leaf_nodes(root_golden), key=lambda z: z.start)
    for g_leaf in leaves_g:
        f_leaf = fault_map.get(g_leaf.id)
        marks = []
        if g_leaf.id in D_ids:
            marks.append("[D]")
        if f_leaf is not None and g_leaf.seed != f_leaf.seed:
            marks.append("[!]")
        print("  %-7d %-7d %-20s %-20s  %s" % (
            g_leaf.start,
            g_leaf.id,
            _seed_short(g_leaf.seed, 16),
            _seed_short(f_leaf.seed if f_leaf is not None else None, 16),
            " ".join(marks),
        ))


def demo_fault_visualization(params=None, fault_node=None, overview_depth=3,
                             zoom_depth=3):
    """
    End-to-end demo: sign twice (golden + with a fault at `fault_node`),
    then print three views:
      1. golden tree overview (top few levels)
      2. faulted tree overview, same depth
      3. tree diff zoomed on the subtree containing fault_node

    This is the visualization intended for the paper/notebook.
    """
    if params is None:
        params = LESS_DEBUG
    print("=" * 78)
    print("Fault visualization demo on %s" % params.name)
    print("=" * 78)

    sk, pk, aux = keygen(params, b"V" * params.seed_bytes)
    msg = b"hello-msg"
    salt = b"S" * params.salt_bytes

    golden, tree_root_g, round_seeds_g = sign(params, sk, msg, salt=salt, fault_zero_seed_node=None)
    if fault_node is None:
        # Default: pick a mid-depth internal node.
        internals = [n for n in bfs_nodes(golden["tree_root"])
                     if not n.is_leaf()]
        fault_node = internals[len(internals) // 4].id
    print("chosen fault node id = %d" % fault_node)

    faulted, tree_root_f, round_seeds_f = sign(params, sk, msg, salt=salt, fault_zero_seed_node=fault_node)

    ok_g = verify(params, pk, msg, golden)
    ok_f = verify(params, pk, msg, faulted)
    print("golden  verify = %s" % ok_g)
    print("faulted verify = %s  (Fiat–Shamir self-heals when True)" % ok_f)
    print()

    # View 1: golden overview
    print_tree_ascii(
        golden["tree_root"],
        max_depth=overview_depth,
        fault_node=fault_node,
        title="(1) golden tree overview, depth %d" % overview_depth,
    )
    print()

    # View 2: faulted overview
    print_tree_ascii(
        faulted["tree_root"],
        max_depth=overview_depth,
        fault_node=fault_node,
        title="(2) faulted tree overview, depth %d" % overview_depth,
    )
    print()

    # View 3: diff, zoomed on fault subtree + its ancestors
    # Find a good zoom root: walk up from fault_node by ~2 levels so we
    # see the fault node in context (with siblings).
    nodes_by_id = {n.id: n for n in bfs_nodes(golden["tree_root"])}
    zoom_root = nodes_by_id[fault_node]
    for _ in range(2):
        if zoom_root.parent is not None:
            zoom_root = zoom_root.parent

    # Build the diff centered at zoom_root.
    print("-" * 78)
    print("(3) tree diff, zoomed on subtree rooted at id=%d" % zoom_root.id)
    print("-" * 78)
    print_tree_diff(
        zoom_root,
        # Pair the faulted tree's corresponding subtree:
        next(n for n in bfs_nodes(faulted["tree_root"]) if n.id == zoom_root.id),
        fault_node=fault_node,
        max_depth=zoom_depth,
        title="diff at id=%d (depth %d)" % (zoom_root.id, zoom_depth),
    )
    print()

    # View 4: flat leaf diff
    print_changed_leaves(
        golden["tree_root"],
        faulted["tree_root"],
        fault_node=fault_node,
    )

    diff_graph = visualize_tree_diff(tree_root_g, tree_root_f, fault_id=zoom_root)

    # In a Jupyter notebook, simply typing 'diff_graph' will render it.
    # Or save to a file:
    diff_graph.render("less_fault_diff", format="png", cleanup=True)
    print("Visualization saved to less_fault_diff.png")


def print_signature_summary(params, sig):
    print("signature summary")
    print("  cmt       =", short_hex(sig["cmt"], 16))
    print("  salt      =", short_hex(sig["salt"], 16))
    print("  weight    =", sum(sig["challenge"]))
    print("  U size    =", len(sig["U"]))
    print("  U         =", sig["U"])
    print("  path size =", len(sig["path"]))
    print("  withheld count =", len(sig["withheld"]))
    print("  withheld model =", sig.get("withheld_model"))
    if sig.get("fault_zero_seed_node") is not None:
        v = sig["fault_zero_seed_node"]
        print("  fault node=", v)
        print("  D(v) size =", len(descendant_rounds(sig["tree_root"], v)))
        print("  D(v)      =", descendant_rounds(sig["tree_root"], v))


def analyze_fault_pair(params, pk, msg, golden_sig, faulted_sig):
    """
    Build a research-oriented summary for one golden/faulted pair.

    In the explicit-response model, each withheld response directly exposes
    µ*_i = π_tilde_i ∘ µ_e_i ∘ τ_1, so this helper records the rounds where
    the faulted signing yields algebraically usable equations.
    """
    v = faulted_sig.get("fault_zero_seed_node")
    Dv = descendant_rounds(faulted_sig["tree_root"], v) if v is not None else []
    Dv_set = set(Dv)
    ch = golden_sig["challenge"]
    chp = faulted_sig["challenge"]

    rsps_agreeing = 0
    for i in sorted(set(golden_sig["U"]).intersection(faulted_sig["U"])):
        if golden_sig["withheld"][i]["blob"] == faulted_sig["withheld"][i]["blob"]:
            rsps_agreeing += 1

    useful = []
    for i in faulted_sig["U"]:
        if i in Dv_set:
            useful.append({
                "round": i,
                "rsp_blob_hex": faulted_sig["withheld"][i]["blob"].hex(),
            })

    out = {
        "fault_node": v,
        "Dv": Dv,
        "Dv_size": len(Dv),
        "golden_weight": sum(ch),
        "faulted_weight": sum(chp),
        "ch_hamming": sum(1 for a, b in zip(ch, chp) if a != b),
        "rsps_agreeing": rsps_agreeing,
        "useful_dfa_equations": len(useful),
        "useful_rounds": [x["round"] for x in useful],
        "pairs": useful,
    }
    return out


def print_fault_summary(summary, max_pairs=12):
    print("fault summary")
    print("  fault node            =", summary["fault_node"])
    print("  |D(v)|                =", summary["Dv_size"])
    print("  useful equations      =", summary["useful_dfa_equations"])
    print("  useful rounds         =", summary["useful_rounds"][:max_pairs], "..." if len(summary["useful_rounds"]) > max_pairs else "")
    print("  rsps agreeing         =", summary["rsps_agreeing"])
    print("  challenge hamming     =", summary["ch_hamming"])


def demo_real_fault(fault_zero_seed_node):
    params = LESS_252_192
    print("=" * 78)
    print("LESS research model fault demo on", params.name)
    print("=" * 78)
    sk, pk, aux = keygen(params, b"R" * params.seed_bytes)
    msg = b"real-less-msg"
    salt = b"T" * params.salt_bytes

    golden, tree_root_g, round_seeds_g = sign(params, sk, msg, salt=salt, fault_zero_seed_node=None, verbose=True)
    ok_g = verify(params, pk, msg, golden, verbose=True)
    print("golden verify =", ok_g)

    faulted, tree_root_f, round_seeds_f = sign(params, sk, msg, salt=salt, fault_zero_seed_node=fault_zero_seed_node, verbose=True)
    ok_f = verify(params, pk, msg, faulted, verbose=True)
    print("faulted verify =", ok_f)

    summary = analyze_fault_pair(params, pk, msg, golden, faulted)
    print_fault_summary(summary)
    print_signature_summary(params, faulted)
    print_tree_summary(faulted["tree_root"], max_nodes=48)
    



# ---------- Demo ------------------------------------------------------------

def diag_e2e(params, label):
    """
    End-to-end diagnostic: run sign() manually in parallel with verify()'s
    reconstruction, and find the first round where the two disagree.
    """
    print("=" * 66)
    print("diag_e2e on %s" % label)
    print("=" * 66)
    sk, pk, aux = keygen(params, b"K" * params.seed_bytes)
    G0 = aux["G0"]
    G1 = pk["G1"]
    piv1 = pk["piv1"]
    tau1 = aux["tau1"]
    salt = b"S" * params.salt_bytes
    msg = b"smoke-test"
    seedsk = sk["seedsk"]

    # Reproduce sign()'s commitments[] exactly.
    seedtree = shake_digest(params, seedsk + b"|seedtree|", params.seed_bytes)
    tree_root, round_seeds = build_ggm(params, seedtree, salt)

    signer_commits = []
    signer_round = []  # stash mu_e, J, A per round
    for i in range(params.t):
        mu_e_seed = round_seeds[i] + salt + msg + le16(i)
        mu_e = sample_monomial(params, mu_e_seed)
        sys = systematic_data_from_monomial_image(params, G0, mu_e)
        A_bytes = commit_matrix_bytes(params, sys["A"])
        signer_commits.append(A_bytes)
        signer_round.append({
            "mu_e": mu_e,
            "J": sys["J"],
            "A": sys["A"],
            "pi_tilde": sys["pi_tilde"],
        })

    cmt_signer = sha3_digest(params, b"".join(signer_commits) + salt + msg)
    ch = sample_challenge(params, cmt_signer)
    U = [i for i, x in enumerate(ch) if x != 0]

    # Build withheld responses.
    withheld = {}
    for i in U:
        mu_star = monomial_compose(
            params,
            monomial_compose(params, signer_round[i]["pi_tilde"], signer_round[i]["mu_e"]),
            tau1,
        )
        withheld[i] = explicit_rsp_from_monomial(params, mu_star, signer_round[i]["J"])

    path = ggm_path(params, seedtree, salt, U)

    # Now simulate verify()'s reconstruction.
    rebuilt = rebuild_ggm(params, path, salt, U)

    verifier_commits = []
    for i in range(params.t):
        if ch[i] == 0:
            if i not in rebuilt:
                print("  round %d: rebuild_ggm did not recover seed" % i)
                return False
            mu_e_seed = rebuilt[i] + salt + msg + le16(i)
            mu_e = sample_monomial(params, mu_e_seed)
            sys_v = systematic_data_from_monomial_image(params, G0, mu_e)
            A_bytes = commit_matrix_bytes(params, sys_v["A"])
        else:
            mu_star = explicit_rsp_to_monomial(params, withheld[i])
            sys_v = systematic_data_with_forced_J(
                params, G1, mu_star, list(range(params.k))
            )
            A_bytes = commit_matrix_bytes(params, sys_v["A"])
        verifier_commits.append(A_bytes)

    # Compare round by round.
    mismatches_published = []
    mismatches_withheld = []
    for i in range(params.t):
        if signer_commits[i] != verifier_commits[i]:
            if ch[i] == 0:
                mismatches_published.append(i)
            else:
                mismatches_withheld.append(i)

    print("Total rounds             :", params.t)
    print("U size                   :", len(U))
    print("Mismatches on PUBLISHED  :", len(mismatches_published))
    print("Mismatches on WITHHELD   :", len(mismatches_withheld))
    if mismatches_published:
        print("  first published mismatch: round", mismatches_published[0])
        i = mismatches_published[0]
        print("    signer   A[0][:8] =", [int(x) for x in signer_round[i]["A"].row(0)][:8])
        print("    (verifier recomputed same way; compare the rebuilt seed to the golden)")
        print("    rebuilt seed match:", rebuilt.get(i) == round_seeds[i])
    if mismatches_withheld:
        print("  first withheld mismatch: round", mismatches_withheld[0])
    cmt_verifier = sha3_digest(params, b"".join(verifier_commits) + salt + msg)
    print("cmt match                :", cmt_signer == cmt_verifier)
    print()


def smoke_test(params, label, message=b"smoke-test", verbose=False):
    """
    End-to-end round-trip check. Prints pass/fail and intermediate counts.
    Use this first to validate that signer and verifier agree on the
    non-pivot block A across all rounds.
    """
    print("-" * 60)
    print("smoke test on %s" % label)
    print("-" * 60)
    sk, pk, aux = keygen(params, b"K" * params.seed_bytes)
    salt = b"S" * params.salt_bytes
    sig = sign(params, sk, message, salt=salt, verbose=verbose)
    ok = verify(params, pk, message, sig, verbose=verbose)
    print("  challenge weight     =", sum(sig["challenge"]))
    print("  withheld (U) size    =", len(sig["U"]))
    print("  path nodes           =", len(sig["path"]))
    print("  verify result        =", ok)
    print()
    return ok


def diag_round(params, label):
    """
    Deep diagnostic for the FIRST withheld round of a sign(). Prints the
    signer-side and verifier-side non-pivot blocks A side-by-side so you
    can see exactly where they differ.

    If A_sign == A_ver as matrices: the problem is elsewhere (serialization,
    digest framing, etc.).
    If A_sign differs from A_ver: the info-set / composition derivation is
    wrong. The printout also shows A_ver for several candidate info-sets
    to help localize the error.
    """
    print("=" * 66)
    print("diag_round on %s" % label)
    print("=" * 66)
    sk, pk, aux = keygen(params, b"K" * params.seed_bytes)
    G0 = aux["G0"]
    G1 = pk["G1"]
    tau1 = aux["tau1"]
    salt = b"S" * params.salt_bytes
    msg = b"diag"
    seedsk = sk["seedsk"]
    seedtree = shake_digest(params, seedsk + b"|seedtree|", params.seed_bytes)
    tree_root, round_seeds = build_ggm(params, seedtree, salt)

    # Produce the full signer state for round 0 EXACTLY like sign() does.
    i = 0
    mu_e_seed = round_seeds[i] + salt + msg + le16(i)
    mu_e = sample_monomial(params, mu_e_seed)
    sys_sign = systematic_data_from_monomial_image(params, G0, mu_e)
    A_sign = sys_sign["A"]
    J_sign = sys_sign["J"]
    pi_tilde = sys_sign["pi_tilde"]
    print("J_sign (info-set, sorted image of [0..k-1] under mu_e.pi):")
    print("  ", J_sign)
    print("pi_tilde.pi:", list(pi_tilde.pi))
    print("pi_tilde.u :", [int(x) for x in pi_tilde.u])
    print("mu_e.pi[0..k-1] =", list(mu_e.pi[:params.k]))
    print("mu_e.u [0..k-1] =", [int(x) for x in mu_e.u[:params.k]])

    mu_star = monomial_compose(
        params,
        monomial_compose(params, pi_tilde, mu_e),
        tau1,
    )
    print("mu_star.pi[0..k-1] =", list(mu_star.pi[:params.k]))

    # Verifier side: compute G_full and try several info-sets for A_ver.
    G_full = apply_monomial(params, G1, mu_star)

    def try_J(J_try, name):
        try:
            sys_v = systematic_data_with_forced_J(params, G1, mu_star, J_try)
            A = sys_v["A"]
            eq = (A == A_sign)
            tag = "MATCH" if eq else "differ"
            print("  verifier with J = %s : %s" % (name, tag))
            if not eq:
                # Show how they differ in size / first row.
                print("    A_sign.nrows/ncols = %d x %d, first row = %s"
                      % (A_sign.nrows(), A_sign.ncols(),
                         [int(x) for x in A_sign.row(0)][:8]))
                print("    A_ver .nrows/ncols = %d x %d, first row = %s"
                      % (A.nrows(), A.ncols(),
                         [int(x) for x in A.row(0)][:8]))
        except ValueError as e:
            print("  verifier with J = %s : invalid (%s)" % (name, e))

    print("Trying candidate information sets on verifier side:")
    try_J(list(range(params.k)),              "{0..k-1}")
    try_J(J_sign,                             "J_sign")
    try_J(list(pk["piv1"]),                   "piv1 (G1's pivots)")
    try_J(sorted(int(x) for x in mu_star.pi[:params.k]), "mu_star.pi[0..k-1]")
    # As a last resort, ask Sage to find an info-set of G_full.
    try:
        piv_full = list(G_full.echelon_form().pivots())
        try_J(piv_full, "echelon pivots of G_full")
    except Exception as e:
        print("  echelon pivots computation failed:", e)
    print()


def demo_debug():
    params = LESS_DEBUG
    print("=" * 78)
    print("LESS research-grade model demo on", params.name)
    print("=" * 78)
    sk, pk, aux = keygen(params, b"D" * params.seed_bytes)
    print("sk = {}".format(sk))
    msg = b"hello-less"
    sig = sign(params, sk, msg, salt=b"S" * params.salt_bytes, verbose=True)
    ok = verify(params, pk, msg, sig, verbose=True)
    print_signature_summary(params, sig)
    print_tree_summary(sig["tree_root"], max_nodes=32)
    print("demo result:", ok)


def demo_real(fault_zero_seed_node=None):
    params = LESS_252_192
    print("=" * 78)
    print("LESS research-grade model demo on", params.name)
    print("=" * 78)
    sk, pk, aux = keygen(params, b"R" * params.seed_bytes)
    print("sk = {}".format(sk))
    msg = b"real-less-msg"
    sig = sign(
        params,
        sk,
        msg,
        salt=b"T" * params.salt_bytes,
        verbose=True,
    )
    ok = verify(params, pk, msg, sig, verbose=True)
    print_signature_summary(params, sig)
    print_tree_summary(sig["tree_root"], max_nodes=48)
    print("demo result:", ok)


# Diagnostic mode: run smoke tests, then a deep diagnostic on the DEBUG
# params to find where signer and verifier disagree.
ok_debug = smoke_test(LESS_DEBUG, "LESS-DEBUG")
ok_real  = smoke_test(LESS_252_192, "LESS-252-192")
if not ok_debug:
    print("DEBUG smoke test FAILED — diagnostics below")
    diag_round(LESS_DEBUG, "LESS-DEBUG")
    diag_e2e(LESS_DEBUG, "LESS-DEBUG")
elif not ok_real:
    print("LESS-252-192 smoke test FAILED — diagnostics below")
    diag_round(LESS_252_192, "LESS-252-192")
else:
    print("=" * 60)
    print("Both smoke tests PASSED.")
    print("=" * 60)
    # Fault visualization on the small params: readable end-to-end.
    #demo_fault_visualization(params=LESS_DEBUG, fault_node=None)
    #print()
    # Fault visualization on LESS-252-192: overview truncated to depth 3
    # (otherwise unreadable), zoom depth 3.
    # Pick a mid-tree node. For T=192 the subroot ids are 1 and 256;
    # pick id=2 (left grandchild of root) for a meaty subtree to fault.
    demo_fault_visualization(params=LESS_252_192, fault_node=352,
                              overview_depth=3, zoom_depth=3)
#if __name__ == "__main__":
#    import sys
#    if len(sys.argv) >= 2 and sys.argv[1] == "debug":
#        demo_debug()
#    elif len(sys.argv) >= 2 and sys.argv[1] == "real":
#        node = int(sys.argv[2]) if len(sys.argv) >= 3 else None
#        demo_real(node)
#    else:
#        print("Usage:")
#        print("  sage full_less_sagemath_prototype.sage debug")
#        print("  sage full_less_sagemath_prototype.sage real [fault_node_id]")
