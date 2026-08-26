"""Merge the C and Mojo benchmark outputs into one table."""
import sys


def parse_c(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4 and parts[0] and not parts[0].startswith("Benchmark"):
                try:
                    out[parts[0]] = float(parts[1])
                except ValueError:
                    pass
    return out


def parse_mojo(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            if line.startswith(("Benchmark", "(", " ")) or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            # the name may contain spaces; the last three columns are numbers
            try:
                lo = float(parts[-3])
            except ValueError:
                continue
            out[" ".join(parts[:-3])] = lo
    return out


# Mojo benchmark name -> C benchmark name
PAIRS = [
    ("ecdsa_verify", "ecdsa_verify"),
    ("ecdsa_sign", "ecdsa_sign"),
    ("ec_keygen", "ec_keygen"),
    ("ecdh", "ecdh"),
    ("ecdsa_recover", "ecdsa_recover"),
    ("ecmult_gen (k*G, const time)", None),
    ("ecmult (na*A + ng*G)", None),
    ("ecmult_var (na*A)", None),
    ("ecmult_const (k*A, const time)", None),
    ("scalar_mul", "scalar_mul"),
    ("scalar_inverse", "scalar_inverse"),
    ("scalar_inverse_var", "scalar_inverse_var"),
    ("scalar_split", "scalar_split"),
    ("field_mul", "field_mul"),
    ("field_sqr", "field_sqr"),
    ("field_inverse", "field_inverse"),
    ("field_inverse_var", "field_inverse_var"),
    ("group_double", "group_double_var"),
    ("group_add_var", "group_add_var"),
    ("group_add_affine", "group_add_affine_var"),
    ("group_to_affine_var", "group_to_affine_var"),
    ("hash_sha256", "hash_sha256"),
    ("hash_hmac_sha256", "hash_hmac_sha256"),
]


def fmt(v):
    if v is None:
        return "-"
    if v >= 100:
        return f"{v:.0f}"
    if v >= 1:
        return f"{v:.3g}"
    return f"{v:.4g}"


def merge_min(dicts):
    """Per-row minimum across repeated runs.

    Both benchmarks already report the minimum within a run; taking the
    minimum across runs as well is what makes the numbers reproducible on a
    machine that is doing anything else at the same time.
    """
    out = {}
    for d in dicts:
        for k, v in d.items():
            if k not in out or v < out[k]:
                out[k] = v
    return out


def main():
    args = sys.argv[1:]
    split = args.index("--mojo")
    c = merge_min([parse_c(p) for p in args[:split]])
    m = merge_min([parse_mojo(p) for p in args[split + 1:]])

    print()
    print(f"{'Operation':<32}{'C (us)':>12}{'Mojo (us)':>12}{'Mojo/C':>10}")
    print("-" * 66)
    for mojo_name, c_name in PAIRS:
        mv = m.get(mojo_name)
        cv = c.get(c_name) if c_name else None
        if mv is None:
            continue
        ratio = f"{mv / cv:.2f}x" if cv else "-"
        print(f"{mojo_name:<32}{fmt(cv):>12}{fmt(mv):>12}{ratio:>10}")
    print()
    print("Lower is better. Ratios under 1.00x mean the Mojo port is faster.")
    print("Each figure is the minimum over repeated runs of both suites.")


if __name__ == "__main__":
    main()
