"""Small helpers shared by the secp256k1 modules and their tests."""


def hex_to_bytes(s: StringSlice) raises -> List[UInt8]:
    """Decode a hex string into bytes. Raises on odd length or bad digits."""
    var b = s.as_bytes()
    var n = len(b)
    if n % 2 != 0:
        raise Error("hex string has odd length")
    var out = List[UInt8](capacity=n // 2)
    var i = 0
    while i < n:
        out.append((_nibble(b[i]) << 4) | _nibble(b[i + 1]))
        i += 2
    return out^


def _nibble(c: UInt8) raises -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    raise Error("invalid hex digit")


comptime _HEX_DIGITS = "0123456789abcdef"


def bytes_to_hex(b: Span[UInt8, _]) -> String:
    var out = String()
    for i in range(len(b)):
        var v = Int(b[i])
        out += _HEX_DIGITS[byte=v >> 4]
        out += _HEX_DIGITS[byte=v & 0xF]
    return out^
