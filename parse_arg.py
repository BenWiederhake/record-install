#!/usr/bin/env python3

import logging
import inspect
import lark

# # ("bitset", re.compile(r"^([A-Z][A-Z0-9_|]+)(?:, |$)")),
# # ("decimal", re.compile(r"^(-?[0-9]+)(?:, |$)")),
# # ("hexadecimal", re.compile(r"^(0x[0-9a-f]+)(?:, |$)")),
# # ("string", re.compile(r'^("(?:[^"\\]|\\.)*"(?:\.\.\.)?)(?:, |$)')),
# # ("fdstring", re.compile(r'^([0-9]+)<([^<>]+(?:<[^<>]+>)?)>(?:, |$)')),
# ("fdset", re.compile(r'^(\[\{(?:(?!\}\]).)*\}\])(?:, |$)')),
# ("struct", re.compile(r'^(\{[^}]+\})(?:, |$)')),
# ("flagset", re.compile(r'^(~?\[[A-Z0-9_ ]*\])(?:, |$)')),
# ("dents", re.compile(r'^(0x[0-9a-f]+) /\* ([0-9]+) entries \*/(?:, |$)')),
int_tree_grammar = r"""
    arg_list: (arg (", " arg)*)?
    arg: "-" uint_b10 -> arg_neg_int_b10
        | uint_b16 -> arg_uint_b16
        | uint_b10
        | identifier
        | identifier ("|" identifier)+ -> arg_bitset
        | "\"" escaped_string? "\"" (dotdotdot)?

    // I'm unhappy about this recursive construction, but can't come up with a better idea:
    escaped_string: octal_digit escaped_string? | escaped_string_nonoctal
    escaped_string_nonoctal: char_string_nonoctal escaped_string?
        | escape_sequence_closed escaped_string?
        | escape_sequence_open escaped_string_nonoctal?
    escape_sequence_closed: "\\" escape_literal -> escaped_character
        | "\\" escape_three_octal
    escape_sequence_open: "\\" escape_short_octal

    // escaped_string: (CHAR_STRING | escape_sequence_common | escape_short_string_start CHAR_STRING_NONOCTAL)*  escape_short_string_start? "\""
    // FIXME: escape_short_string_start CAN BE FOLLOWED BY escape_short_string_start

    // arg: identifier -> arg_ident
    //     | identifier (PIPE identifier)+ -> arg_bitset
    //     | "-" uint_b10 -> arg_neg_int_b10
    //     | uint_b16 -> arg_uint_b16
    //     | uint_b10 // …
    //     //| "\"" escaped_string "\"" maybe_string_continuation -> arg_string
    //     //| uint_b10 (LESS escaped_path (LESS escaped_path () GREATER)? GREATER)? -> arg_path_or_int_b10
    // identifier: /[A-Z][A-Z0-9_]+/ -> token_value
    // uint_b10: /0(?!x)|[1-9][0-9]*/
    // uint_b16: /0x[0-9a-f]+/
    // escaped_string: escaped_string_part*
    // !escaped_string_part: "<" | ">" -> token_value
    //     | escaped_path_part -> from_common_escape
    // escaped_path: escaped_path_part* -> escaped_string
    // escaped_path_part: /[^<>"\\]/ -> token_value
    //     | common_escape -> from_common_escape
    // common_escape: "\\" /[tnvfr"\\]/ -> escaped_character
    //     | BACKSLASH /(0|[1-7][0-7]?)(?![0-7])/ -> numeric_character
    //     | BACKSLASH /[0-3][0-7][0-7]/ -> numeric_character
    // maybe_string_continuation: (DOT DOT DOT)?

    // Lark has lots of trouble with regexes that have *any* overlap.
    // Regexes are:
    // * Anything written in all-caps (e.g. 'DIGIT: "asdf"')
    // * Anything written in range notation (e.g. '"0".."9"')
    // * Any literal regex (e.g. '/a*(bc)+/')
    // Overlapping string literals are fine, but MUST NOT overlap with any of the regexes.
    // Therefore, try to avoid regexes as much as possible.
    !dotdotdot: "..."
    !underscore: "_"
    !nonzero_octal_digit: "1" // | "2" | "3" | "4" | "5" | "6" | "7"
    !octal_digit: "0" | nonzero_octal_digit
    !nonzero_decimal_digit: nonzero_octal_digit | "8" | "9"
    !decimal_digit: "0" | nonzero_decimal_digit

    !uint_b10: "0" | nonzero_decimal_digit decimal_digit*
    !uint_b16: "0" "x" hexadecimal_digit+

    !hexadecimal_digit: decimal_digit | "a" | "b" | "c" | "d" | "e" | "f"
    !identifier: char_alpha_upper (char_alpha_upper | decimal_digit | underscore)+
    !escape_literal: "t" | "n" | "v" | "f" | "r" | "\"" | "\\"
    !escape_three_octal: ("0" | "1" | "2" | "3") octal_digit octal_digit
    !escape_short_octal: "0" | nonzero_octal_digit octal_digit?

    // ASCII contains:
    // 1: 0x00 (NUL)
    // 31: 0x01-0x1F (includes some named control chars)
    // 16: 0x20-0x2F » !"#$%&'()*+,-./«
    // 10: 0x30-0x39 "0".."9"
    // 6: 0x3A-0x3F ":;<=>?"
    // 1: 0x40 "@"
    // 32: 0x41-0x5A "A".."Z"
    // 6: 0x5B-0x60 "[\]^_`"
    // 26: 0x61-0x7A "a".."z"
    // 4: 0x7B-0x7E "{|}~"
    // 1: 0x7F DEL

    // Exclude '"', "<", ">", "\\", and all non-printable characters:
    !char_path_nonoctal: " " | "!" | "#" | "$" | "%" | "&" | "'" | "(" | ")" | "*" | "+" | "," | "-" | "." | "/"  // excludes "\""
        | "8" | "9"  // excludes octal characters
        | ":" | ";" | "=" | "?" | "@"  // excludes "<" and ">"
        | char_alpha_upper
        | "[" | "]" | "^" | "_" | "`"  // excludes "\\"
        | char_alpha_lower
        | "{" | "|" | "}" | "~"
    !char_alpha_upper: "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I" | "J" | "K" | "L" | "M" | "N" | "O" | "P" | "Q" | "R" | "S" | "T" | "U" | "V" | "W" | "X" | "Y" | "Z"
    !char_alpha_lower: "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" | "i" | "j" | "k" | "l" | "m" | "n" | "o" | "p" | "q" | "r" | "s" | "t" | "u" | "v" | "w" | "x" | "y" | "z"
    !char_string_nonoctal: char_path_nonoctal | "<" | ">"
    """

ESCAPE_CHAR_TO_CHAR = {
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
}

lark.logger.setLevel(logging.DEBUG)
inline_args = lark.v_args(inline=True)


def see(x):
    print(f"{inspect.stack()[1][3]} sees {repr(x)}")


class MyTransformer(lark.Transformer):
    arg_list = list

    def prefix(self, args):
        return len(args)

    @inline_args
    def arg_ident(self, identifier):
        return {"type": "identifier", "name": identifier}

    def arg_bitset(self, identifiers):
        return {"type": "bitset", "values": identifiers}

    @inline_args
    def arg_neg_int_b10(self, value):
        return {"type": "int_b10", "value": -value}

    @inline_args
    def arg_uint_b16(self, value):
        return {"type": "uint_b16", "value": value}

    @inline_args
    def token_value(self, token):
        return token.value

    @inline_args
    def uint_b10(self, digits):
        return int(digits.value)

    @inline_args
    def uint_b16(self, digits):
        return int(digits.value, 16)

    def maybe_string_continuation(self, parts):
        assert parts == [] or parts == ["..."]
        if parts:
            return "incomplete"
        else:
            return "complete"

    @inline_args
    def escaped_character(self, char):
        return ESCAPE_CHAR_TO_CHAR[char.value]

    def escaped_string(self, parts):
        str_parts = []
        for i, p in enumerate(parts):
            if isinstance(p, str):
                str_parts.append(p)
            else:
                print(f"ERROR: part#{i + 1} is not a str: >>{p}<<")
        return "".join(str_parts)

    @inline_args
    def numeric_character(self, char):
        return chr(int(char.value, 8))

    @inline_args
    def from_common_escape(self, string):
        return string

    @inline_args
    def arg_string(self, string, rest):
        assert rest in ["complete", "incomplete"]
        return {
            "type": "string",
            "value": string,
            "complete": rest == "complete",
        }

    @inline_args
    def arg_path_or_int_b10(self, fd, path=None, metadata=None):
        assert path is not None or metadata is None  # "metadata implies path"
        if path is None:
            return {"type": "int_b10", "value": fd}
        return {
            "type": "fd",
            "value": fd,
            "path": path,
            "metadata": metadata,
        }


TRANSFORMER = MyTransformer()

arg_list_parser = lark.Lark(int_tree_grammar, start="arg_list", parser="lalr", debug=True)


def run_expectation(test_index, input_string, expected):
    print(f"[P{test_index:03}] Testing '{input_string}' ... ", end="")
    try:
        actual = arg_list_parser.parse(input_string)
        #actual = TRANSFORMER.transform(arg_list_parser.parse(input_string))
    except ValueError as e:
        print(f"\nERROR: {e}")
        return
    if actual != expected:
        print()
        print(f"ERROR: Expected {expected} instead")
        print(f"       Actual = {actual}")
        print(actual.pretty())
        return
    print("ok")


EXPECTATIONS = [
    ('', []),
    ('FOO', [{"type": "identifier", "name": "FOO"}]),
    ('FOO, BAR', [{"type": "identifier", "name": "FOO"}, {"type": "identifier", "name": "BAR"}]),
    ('FOO, BAR, BAZ', [{"type": "identifier", "name": "FOO"}, {"type": "identifier", "name": "BAR"}, {"type": "identifier", "name": "BAZ"}]),
    ('FOO, BAR, BAZ, QUUX', [{"type": "identifier", "name": "FOO"}, {"type": "identifier", "name": "BAR"}, {"type": "identifier", "name": "BAZ"}, {"type": "identifier", "name": "QUUX"}]),
    ('FOO|BAR', [{"type": "bitset", "values": ["FOO", "BAR"]}]),
    ('FOO|BAR|BAZ', [{"type": "bitset", "values": ["FOO", "BAR", "BAZ"]}]),
    ('FOO|BAR, BAZ|QUUX', [{"type": "bitset", "values": ["FOO", "BAR"]}, {"type": "bitset", "values": ["BAZ", "QUUX"]}]),
    ('0', [{"type": "int_b10", "value": 0}]),
    ('123', [{"type": "int_b10", "value": 123}]),
    ('-1234567', [{"type": "int_b10", "value": -1234567}]),
    ('9223372036854775807', [{"type": "int_b10", "value": 9223372036854775807}]),
    ('-9223372036854775808', [{"type": "int_b10", "value": -9223372036854775808}]),
    ('0x0', [{"type": "uint_b16", "value": 0x0}]),
    ('0x123', [{"type": "uint_b16", "value": 0x123}]),
    ('0x1234567', [{"type": "uint_b16", "value": 0x1234567}]),
    ('0x123456789abcdef0', [{"type": "uint_b16", "value": 0x123456789abcdef0}]),
    ('"hello"', [{"type": "string", "value": "hello", "complete": True}]),
    ('"FOO"', [{"type": "string", "value": "hello", "complete": True}]),
    ('"0asdf"', [{"type": "string", "value": "0asdf", "complete": True}]),
    ('"qwer0asdf"', [{"type": "string", "value": "qwer0asdf", "complete": True}]),
    ('""', [{"type": "string", "value": "", "complete": True}]),
    ('"world"...', [{"type": "string", "value": "world", "complete": False}]),
    ('""...', [{"type": "string", "value": "", "complete": False}]),
    # This is a really wacky encoding.
    (r'"really\1weird"', [{"type": "string", "value": "really\x01weird", "complete": True}]),
    (r'"really\10weird"', [{"type": "string", "value": "really\x08weird", "complete": True}]),
    (r'"really\100weird"', [{"type": "string", "value": "really\x40weird", "complete": True}]),
    (r'"really\0010weird"', [{"type": "string", "value": "really\x010weird", "complete": True}]),
    (r'"really\0100weird"', [{"type": "string", "value": "really\x080weird", "complete": True}]),
    (r'"really\1000weird"', [{"type": "string", "value": "really\x400weird", "complete": True}]),
    (r'"really\tweird"', [{"type": "string", "value": "really\x09weird", "complete": True}]),
    (r'"really\nweird"', [{"type": "string", "value": "really\x0aweird", "complete": True}]),
    (r'"really\vweird"', [{"type": "string", "value": "really\x0bweird", "complete": True}]),
    (r'"really\fweird"', [{"type": "string", "value": "really\x0cweird", "complete": True}]),
    (r'"really\rweird"', [{"type": "string", "value": "really\x0dweird", "complete": True}]),
    (r'"really\"weird"', [{"type": "string", "value": "really\x22weird", "complete": True}]),
    (r'"really\\weird"', [{"type": "string", "value": "really\x5cweird", "complete": True}]),
    (r'"really\177weird"', [{"type": "string", "value": "really\x7fweird", "complete": True}]),
    (r'"really\200weird"', [{"type": "string", "value": "really\x80weird", "complete": True}]),
    (r'"really\234weird"', [{"type": "string", "value": "really\x9cweird", "complete": True}]),
    (r'"really\345weird"', [{"type": "string", "value": "really\xe5weird", "complete": True}]),
    (r'"really\377weird"', [{"type": "string", "value": "really\xffweird", "complete": True}]),
    (r'"really\08weird"', [{"type": "string", "value": "really\x008weird", "complete": True}]),
    (r'"really\18weird"', [{"type": "string", "value": "really\x018weird", "complete": True}]),
    (r'"really\28weird"', [{"type": "string", "value": "really\x028weird", "complete": True}]),
    (r'"really\38weird"', [{"type": "string", "value": "really\x038weird", "complete": True}]),
    (r'"really\48weird"', [{"type": "string", "value": "really\x048weird", "complete": True}]),
    (r'"really\58weird"', [{"type": "string", "value": "really\x058weird", "complete": True}]),
    (r'"really\68weird"', [{"type": "string", "value": "really\x068weird", "complete": True}]),
    (r'"really\78weird"', [{"type": "string", "value": "really\x078weird", "complete": True}]),
    (r'"really\108weird"', [{"type": "string", "value": "really\x088weird", "complete": True}]),
    (r'"really\208weird"', [{"type": "string", "value": "really\x108weird", "complete": True}]),
    (r'"really\218weird"', [{"type": "string", "value": "really\x118weird", "complete": True}]),
    (r'"sanity<check>"', [{"type": "string", "value": "sanity<check>", "complete": True}]),
    (r'"sanity,check>"', [{"type": "string", "value": "sanity,check>", "complete": True}]),
    (r'"sanity check>"', [{"type": "string", "value": "sanity check>", "complete": True}]),
    (r'"sanity, check>"', [{"type": "string", "value": "sanity, check>", "complete": True}]),
    # # fdstrings without the string cannot possibly recognized as such. We shift that responsibility to the user.
    # (r'1', [{"type": "int_b10", "value": 1}]),
    # (r'1</dev/null>', [{"type": "fd", "value": 1, "path": "/dev/null", "metadata": None}]),
    # (r'1</dev/null<char 1:3>>', [{"type": "fd", "value": 1, "path": "/dev/null", "metadata": "char 1:3"}]),
    # (r'3</tmp/x/THE\"MARKER>', [{"type": "fd", "value": 3, "path": "/tmp/x/THE\"MARKER", "metadata": None}]),
]

NEGATIVES = [
    ('['),
    (']'),
    ('"'),
    (', '),
    ('FOO, '),
    (', BAR'),
    ('FOO,BAR'),
    ('+7'),
    ('-0x123'),
    ('-3</tmp/foo>'),
    ('0123'),
    ('1234a'),
    ('"hello\\"'),
    ("'hello'"),
    ('42...'),
    (r'"really\03weird"'),
    (r'"really\8weird"'),
    (r'<barepath>'),
    (r'<barepath<char 1:3>>'),
]
NEGATIVES = []  # FIXME

for i, expectation in enumerate(EXPECTATIONS):
    run_expectation(i, *expectation)
for i, input_string in enumerate(NEGATIVES):
    print(f"[N{i:03}] Testing '{input_string}' ... ", end="")
    try:
        tree = arg_list_parser.parse(input_string)
    except (lark.exceptions.UnexpectedCharacters, lark.exceptions.UnexpectedToken, lark.exceptions.UnexpectedEOF):
        print("ok")
        continue
    print(f"\nERROR: Was accepted?!\n{tree}\n{tree.pretty()}")
