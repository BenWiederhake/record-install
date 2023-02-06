#!/bin/false
# This is a library

import logging
import inspect
import lark

arg_list_grammar = r"""
    arg_list: (value (", " value)*)?
    ?value: atom
        | ID "=" atom                         -> named_argument
    ?atom: "[" (value (", " value)*)? "]"        -> list
         | "{" key_value (", " key_value)* [", " complete] "}" -> struct
         | "{" (ID (" " ID)*)? [" " complete] "}" -> ioctl_set
         | ID ("|" (ID | OCT_NUMBER))+        -> bitset
         | "~[" (ID (" " ID)*)? "]"           -> bitset2
         | ID                                 -> identifier
         | "&" ID                             -> reference
         | ID "(" (value (", " value)*)? ")"  -> call
         | FD_START FD_MAIN [">" FD_MAIN] (FD_META | ">")     -> fd
         | OCT_NUMBER                         -> oct_number
         | DEC_NUMBER ["*" DEC_NUMBER]        -> dec_number
         | "[" DEC_NUMBER "->" DEC_NUMBER "]" -> partial_length
         | HEX_NUMBER [" /* " DEC_NUMBER " " ID " */"] -> hex_number
         | STRING [complete]                  -> string
         | "[{WIFEXITED(s) && WEXITSTATUS(s) == " DEC_NUMBER "}]" -> exit_status
    complete: "..."
    key_value: /inet_pton\(/ value ", " value ", " value ")" -> fake_inet_pton_kv
         | ID "=" value
    ID: /(?!0[x<0-9])(?!inet_pton)[A-Za-z0-9_]+/
    FD_START.2: /\d+</
    FD_MAIN.1: /((?<!>)|(?<=->))[^<>]+/
    FD_META: /<[^<>]*>>/
    HEX_NUMBER: /0x[\dA-Fa-f]+(?!\w)/
    DEC_NUMBER.1: /-?(0(?![x<0-9])|[1-9][0-9]*)(?!x0-9)/
    OCT_NUMBER: /0([0-7]+)(?!0-9)/
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

    def reference(self, name):
        return {"type": "reference", "name": name.value}

    def bitset(self, *values):
        return {"type": "bitset", "values": [v.value for v in values]}

    def bitset2(self, *values):
        return {"type": "bitset2", "values": [v.value for v in values]}

    def oct_number(self, value):
        return {"type": "uint_b8", "value": int(value, 8)}

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
                elif len(token) > i and token[i] == "x":
                    hexcode = token[i + 1 : i + 3]
                    if len(hexcode) != 2:
                        raise EscapeError(f"Invalid hex code {hexcode!r}")
                    out += chr(int(hexcode, 16))
                    i += 3
                elif len(token) > i and token[i] in ESCAPE_CHAR_TO_CHAR:
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

    def fd(self, start, main, main_continue, meta=None):
        if main_continue is not None:
            main = main + ">" + main_continue
        return {"type": "fd", "value": int(start[:-1]), "path": self.STRING('"' + main + '"'),
                "metadata": None if meta is None else meta[1:-2]}

    def list(self, *children):
        return {"type": "list", "children": list(children)}

    def key_value(self, key, value):
        return (key.value, value)

    def fake_inet_pton_kv(self, self_name, *args):
        # This is *so* stupid.
        self_name.value = self_name.value[: -1]
        return self.key_value(self_name, self.call(self_name, *args))

    def struct(self, *pairs_and_complete_marker):
        pairs = pairs_and_complete_marker[:-1]
        complete_marker = pairs_and_complete_marker[-1]
        struct_dict = dict()
        for key, value in pairs:
            if key in struct_dict:
                raise EscapeError(f"Duplicate key {key!r}?!")
            struct_dict[key] = value
        return {"type": "struct", "complete": complete_marker is None, "items": struct_dict}

    def call(self, fn_name, *args):
        return {"type": "call", "function": fn_name.value, "args": list(args)}

    def exit_status(self, exit_code):
        return {"type": "exit_status", "value": int(exit_code)}

    def named_argument(self, arg_name, value):
        return {"type": "named_arg", "name": arg_name.value, "value": value}

    def ioctl_set(self, *ioctls_and_complete_marker):
        ioctls = ioctls_and_complete_marker[:-1]
        ioctls = [e.value for e in ioctls]
        complete_marker = ioctls_and_complete_marker[-1]
        return {"type": "ioctl_set", "complete": complete_marker is None, "values": ioctls}

    def partial_length(self, provided, actual):
        return {"type": "partial_length", "provided": int(provided), "actual": int(actual)}


lark.logger.setLevel(logging.DEBUG)
TRANSFORMER = ArgListTransformer()
arg_list_parser = lark.Lark(arg_list_grammar, start="arg_list", parser="lalr", debug=True)
