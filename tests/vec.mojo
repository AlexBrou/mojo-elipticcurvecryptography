"""Loader for the C-generated test vector files under tests/vectors/."""

from std.pathlib import Path


@fieldwise_init
struct Row(Copyable):
    var op: String
    var args: List[String]

    def arg(self, i: Int) -> String:
        return self.args[i]


def load(name: String) raises -> List[Row]:
    var text = Path("tests/vectors/" + name).read_text()
    var rows = List[Row]()
    for line in text.split("\n"):
        var s = line.strip()
        if s.byte_length() == 0 or s.startswith("#"):
            continue
        # Keep empty fields: a zero-length hex argument (the empty message in
        # the SHA-256 vectors) shows up as an empty field and must not shift
        # the remaining columns.
        var parts = List[String]()
        for p in s.split(" "):
            parts.append(String(p))
        if len(parts) < 2:
            continue
        var op = parts[0]
        var args = List[String]()
        for i in range(1, len(parts)):
            args.append(parts[i])
        rows.append(Row(op, args^))
    return rows^


def filter(rows: List[Row], op: String) -> List[Row]:
    var out = List[Row]()
    for r in rows:
        if r.op == op:
            out.append(r.copy())
    return out^
