#!/bin/false
# This is a library

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

# [{fd=0</dev/pts/8<char 136:8>>, events=0}, {fd=1<pipe:[41666807]>, events=0}, {fd=2<pipe:[41666807]>, events=0}]
# {st_mode=S_IFREG|0644, st_size=112286, ...}
# ~[RTMIN RT_1]
arg_list_grammar = r"""
    arg_list: (value (", " value)*)?
    ?value: atom
    ?atom: "[" (value (", " value)*)? "]"        -> list
         | "{" key_value (", " key_value)* [", " complete] "}" -> struct
         | ID ("|" ID)+                       -> bitset
         | ID                                 -> identifier
         | FD_START FD_MAIN [FD_META] ">"     -> fd
         | DEC_NUMBER ["*" DEC_NUMBER]        -> dec_number
         | HEX_NUMBER [" /* " DEC_NUMBER " " ID " */"] -> hex_number
         | STRING [complete]                  -> string
    complete: "..."
    key_value: ID "=" value
    ID: /(?!0x)[A-Za-z0-9_]+/
    FD_START.2: /\d+</
    FD_MAIN: /[^<>]+/
    FD_META: /<[^>]*>/
    HEX_NUMBER: /0x[\dA-Fa-f]+(?!\w)/
    DEC_NUMBER.1: /-?(0(?!x)|[1-9][0-9]*)(?!x)/ // \d+(?!\w)
    STRING: /"([^\\\\"]|\\.)*"/
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
OCTAL_DIGITS = "01234567"


def see(x):
    print(f"{inspect.stack()[1][3]} sees {repr(x)} = '{x}'")


class EscapeError(Exception):
    pass


@lark.v_args(inline=True)
class ArgListTransformer(lark.Transformer):
    def arg_list(self, *children):
        return list(children)

    def identifier(self, name):
        return {"type": "identifier", "name": name.value}

    def bitset(self, *values):
        return {"type": "bitset", "values": [v.value for v in values]}

    def dec_number(self, value, factor):
        if factor is not None:
            return {"type": "int_b10", "value": int(value), "factor": int(factor)}
        return {"type": "int_b10", "value": int(value)}

    def hex_number(self, value, num_comment, unit_comment):
        assert (num_comment is None) == (unit_comment is None)
        if num_comment is not None:
            return {"type": "uint_b16", "value": int(value[2:], 16), "num": int(num_comment.value), "unit": unit_comment.value}
        return {"type": "uint_b16", "value": int(value[2:], 16)}

    def STRING(self, token):
        token = token[1:-1]
        out = ""
        i = 0
        while i < len(token):
            if token[i] == "\\":
                i += 1
                if len(token) > i and token[i] in OCTAL_DIGITS:
                    l = 1
                    if len(token) > i + 1 and token[i + 1] in OCTAL_DIGITS:
                        l += 1
                        if len(token) > i + 2 and token[i + 2] in OCTAL_DIGITS:
                            l += 1
                        elif token[i] == "0":
                            raise EscapeError(f"Invalid octal code {token[i : i+3]!r}")
                    out += chr(int(token[i:i + l], 8))
                    i += l
                elif token[i] in ESCAPE_CHAR_TO_CHAR:
                    out += ESCAPE_CHAR_TO_CHAR[token[i]]
                    i += 1
                else:
                    raise EscapeError(f"Unknown escape sequence {token[i : i+3]!r}")
            else:
                out += token[i]
                i += 1
        return out

    def string(self, value, complete_marker):
        return {"type": "string", "value": value, "complete": not complete_marker}

    def fd(self, start, main, meta):
        return {"type": "fd", "value": int(start[:-1]), "path": self.STRING('"' + main + '"'),
                "metadata": None if meta is None else meta[1:-1]}

    def list(self, *children):
        return {"type": "list", "children": list(children)}

    def key_value(self, key, value):
        return (key.value, value)

    def struct(self, *pairs_and_complete_marker):
        pairs = pairs_and_complete_marker[:-1]
        complete_marker = pairs_and_complete_marker[-1]
        struct_dict = dict()
        for key, value in pairs:
            if key in struct_dict:
                raise EscapeError(f"Duplicate key {key!r}?!")
            struct_dict[key] = value
        return {"type": "struct", "complete": complete_marker is None, "items": struct_dict}


lark.logger.setLevel(logging.DEBUG)
TRANSFORMER = ArgListTransformer()
arg_list_parser = lark.Lark(arg_list_grammar, start="arg_list", parser="lalr", debug=True)
