#!/usr/bin/env python3

import lark
import parse_arg
import unittest

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
    ('"FOO"', [{"type": "string", "value": "FOO", "complete": True}]),
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
    # fdstrings without the string cannot possibly recognized as such. We shift that responsibility to the user.
    (r'1', [{"type": "int_b10", "value": 1}]),
    (r'1</dev/null>', [{"type": "fd", "value": 1, "path": "/dev/null", "metadata": None}]),
    (r'1</dev/null<char 1:3>>', [{"type": "fd", "value": 1, "path": "/dev/null", "metadata": "char 1:3"}]),
    (r'3</tmp/x/THE\"MARKER>', [{"type": "fd", "value": 3, "path": "/tmp/x/THE\"MARKER", "metadata": None}]),
    ('3<TCPv6:[41664597]>', [{"type": "fd", "value": 3, "path": "TCPv6:[41664597]", "metadata": None}]),
    ('[1]', [{"type": "list", "complete": True, "children": [{"type": "int_b10", "value": 1}]}]),
    ('[1, 2, 3]', [{"type": "list", "complete": True, "children": [{"type": "int_b10", "value": 1}, {"type": "int_b10", "value": 2}, {"type": "int_b10", "value": 3}]}]),
    ('3<TCPv6:[41664597]>, FIONBIO, [1]', [{"type": "fd", "value": 3, "path": "TCPv6:[41664597]", "metadata": None}, {"type": "identifier", "name": "FIONBIO"}, {"type": "list", "complete": True, "children": [{"type": "int_b10", "value": 1}]}]),
    ('{fd=0</dev/pts/8<char 136:8>>, events=0}', [
        {"type": "struct", "complete": True, "items": [
            {'name': 'fd', 'type': 'named_arg', 'value': {'metadata': 'char 136:8', 'path': '/dev/pts/8', 'type': 'fd', 'value': 0}},
            {'name': 'events', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 0}}
        ]},
    ]),
    ("{st_mode=S_IFDIR|0755, st_size=4096}", [
        {"type": "struct", "complete": True, "items": [
            {'name': 'st_mode', 'type': 'named_arg', 'value': {'type': 'bitset', 'values': ['S_IFDIR', '0755']}},
            {'name': 'st_size', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 4096}},
        ]},
    ]),
    ("{st_mode=S_IFDIR|0755, st_size=4096, ...}", [
        {"type": "struct", "complete": False, "items": [
            {'name': 'st_mode', 'type': 'named_arg', 'value': {'type': 'bitset', 'values': ['S_IFDIR', '0755']}},
            {'name': 'st_size', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 4096}},
        ]},
    ]),
    (r'"TZif2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\t\0\0\0\t\0\0\0\0"...', [{"type": "string", "value": "TZif2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\t\x00\x00\x00\x00", "complete": False}]),
    ('0x1d2b4b0 /* 209 entries */', [{"type": "uint_b16", "value": 0x1d2b4b0, "comment": "209 entries"}]),
    ('0x7fff3018edb8 /* 45 vars */', [{"type": "uint_b16", "value": 0x7fff3018edb8, "comment": "45 vars"}]),
    ('[]', [{"type": "list", "complete": True, "children": []}]),
    ('8192*1024', [{"type": "int_b10", "value": 8192, "factor": 1024}]),
    ("~[RTMIN RT_1]", [{"type": "bitset2", "values": ["RTMIN", "RT_1"]}]),
    ("0123", [{"type": "uint_b8", "value": 0o123}]),
    ("0777", [{"type": "uint_b8", "value": 0o777}]),
    ("3<UDPv6:[[2a02:1234:1234:1234:1234:1234:1234:abcd]:60696->[2a04:1234:1234::1234]:443]>", [{"type": "fd", "value": 3, "path": "UDPv6:[[2a02:1234:1234:1234:1234:1234:1234:abcd]:60696->[2a04:1234:1234::1234]:443]", "metadata": None}]),
    ("htons(443)", [{"type": "call", "function": "htons", "args": [{"type": "int_b10", "value": 443}]}]),
    ("htonl(0)", [{"type": "call", "function": "htonl", "args": [{"type": "int_b10", "value": 0}]}]),
    ('if_nametoindex("enp2s0")', [{"type": "call", "function": "if_nametoindex", "args": [{"type": "string", "value": "enp2s0", "complete": True}]}]),
    ('makedev(0x88, 0x8)', [{"type": "call", "function": "makedev", "args": [{"type": "uint_b16", "value": 0x88}, {"type": "uint_b16", "value": 0x8}]}]),
    ('-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL', [
        {"type": "int_b10", "value": -1},
        {"type": "exit_status", "value": 0},
        {"type": "int_b10", "value": 0},
        {"type": "identifier", "name": "NULL"},
    ]),
    ("child_stack=NULL", [{"type": "named_arg", "name": "child_stack", "value": {"type": "identifier", "name": "NULL"}}]),
    ("{B38400 opost}", [{"type": "ioctl_set", "values": ["B38400", "opost"], "complete": True}]),
    ("{B38400 opost isig icanon echo ...}", [{"type": "ioctl_set", "values": ["B38400", "opost", "isig", "icanon", "echo"], "complete": False}]),
    # This format appears for getrandom and ONLY getrandom.
    # WHY?! Each byte takes up 3 output bytes, but with octal encoding it could be even smaller. So space isn't the reason.
    # Speed doesn't seem reasonable either: getrandom() really shouldn't be called in a tight loop anyway, and accounts for 40 out of 80k syscalls in some sample I made, so speed isn't the reason either.
    (r'"\x2f\xb0\x32\x2f\xce\xc2\x22\xf0"', [{"type": "string", "complete": True, "value": "\x2f\xb0\x32\x2f\xce\xc2\x22\xf0"}]),
    (r'"\xc2\x22\x61\xbf\xbf\x92\x42\x62\x22\xa0\xb0\x32\xb5\x3f\xc2\x03\x22\xd2\x2b\x21\x24\x12\xfd\x61"', [{"type": "string", "complete": True, "value": "\xc2\x22\x61\xbf\xbf\x92\x42\x62\x22\xa0\xb0\x32\xb5\x3f\xc2\x03\x22\xd2\x2b\x21\x24\x12\xfd\x61"}]),
    ("&sin6_addr", [{"type": "reference", "name": "sin6_addr"}]),
    ('{sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2a00:1234:1234::223", &sin6_addr)}', [{
        'type': 'struct',
        'complete': True,
        'items': [
            {'type': 'named_arg', 'name': 'sa_family', 'value': {'name': 'AF_INET6', 'type': 'identifier'}},
            {'type': 'named_arg', 'name': 'sin6_port', 'value': {'args': [{'type': 'int_b10', 'value': 443}], 'function': 'htons', 'type': 'call'}},
            {'type': 'named_arg', 'name': 'sin6_flowinfo', 'value': {'args': [{'type': 'int_b10', 'value': 0}], 'function': 'htonl', 'type': 'call'}},
            {'type': 'call', 'function': 'inet_pton', 'args': [
                {'name': 'AF_INET6', 'type': 'identifier'},
                {'type': 'string', 'complete': True, 'value': '2a00:1234:1234::223'},
                {'type': 'reference', 'name': 'sin6_addr'}
            ]}
        ],
    }]),
    ("[28->16]", [{"type": "list", "complete": True, "children": [{"type": "partial_length", "provided": 28, "actual": 16}]}]),
    ("[128->28]", [{"type": "list", "complete": True, "children": [{"type": "partial_length", "provided": 128, "actual": 28}]}]),
    # The following two examples are from real-life. I wish strace would output something saner.
    ("{{len=20, type=NLMSG_DONE, flags=NLM_F_MULTI, seq=1234567890, pid=1234567}, 0}", [{
        'type': 'struct',
        'complete': True,
        'items': [
            {'type': 'struct', 'complete': True, 'items': [
                {'name': 'len', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 20}},
                {'name': 'type', 'type': 'named_arg', 'value': {'name': 'NLMSG_DONE', 'type': 'identifier'}},
                {'name': 'flags', 'type': 'named_arg', 'value': {'name': 'NLM_F_MULTI', 'type': 'identifier'}},
                {'name': 'seq', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 1234567890}},
                {'name': 'pid', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 1234567}}
            ]},
            {'type': 'int_b10', 'value': 0}
        ],
    }]),
    ("{{len=20, type=RTM_GETADDR, flags=NLM_F_REQUEST|NLM_F_DUMP, seq=1234567890, pid=0}, {ifa_family=AF_UNSPEC, ...}}", [{
        'type': 'struct',
        'complete': True,
        'items': [
            {
                'type': 'struct',
                'complete': True,
                'items': [
                    {'name': 'len', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 20}},
                    {'name': 'type', 'type': 'named_arg', 'value': {'name': 'RTM_GETADDR', 'type': 'identifier'}},
                    {'name': 'flags', 'type': 'named_arg', 'value': {'type': 'bitset', 'values': ['NLM_F_REQUEST', 'NLM_F_DUMP']}},
                    {'name': 'seq', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 1234567890}},
                    {'name': 'pid', 'type': 'named_arg', 'value': {'type': 'int_b10', 'value': 0}}
                ],
            },
            {
                'type': 'struct',
                'complete': False,
                'items': [
                    {'name': 'ifa_family', 'type': 'named_arg', 'value': {'name': 'AF_UNSPEC', 'type': 'identifier'}}
                ],
            }
        ],
    }]),
    ("{mask=[]}", [{
        'type': 'struct',
        'complete': True,
        'items': [{'name': 'mask', 'type': 'named_arg', 'value': {'type': 'list', "complete": True, 'children': []}}]
    }]),
    ("[BUS SEGV]", [{'type': 'bitset3', 'values': ['BUS', 'SEGV']}]),
    ("0x29 /* CAP_??? */", [{'type': 'uint_b16', 'value': 0x29, 'comment': 'CAP_???'}]),
    ("{tls=0x7f123456789a} => {parent_tid=[123456]}", [{
        'type': 'inout',
        'in': {'complete': True, 'items': [{'name': 'tls', 'type': 'named_arg', 'value': {'type': 'uint_b16', 'value': 139716164221082}}], 'type': 'struct'},
        'out': {'complete': True, 'items': [{'name': 'parent_tid', 'type': 'named_arg', 'value': {'children': [{'type': 'int_b10', 'value': 123456}], 'type': 'list', "complete": True}}], 'type': 'struct'},
    }]),
    (r'[42, 43, 44, ...]', [{"type": "list", "complete": False, "children": [
        {'type': 'int_b10', 'value': 42}, {'type': 'int_b10', 'value': 43}, {'type': 'int_b10', 'value': 44}
    ]}]),
    (r'msg_namelen=28->16', [{'type': 'named_arg', 'name': 'msg_namelen', 'value': {'type': 'partial_length', 'actual': 16, 'provided': 28}}]),
    # Add more examples here.
]

NEGATIVES = [
    '[',
    ']',
    '"',
    ', ',
    'FOO, ',
    ', BAR',
    'FOO,BAR',
    '+7',
    '-0x123',
    '-3</tmp/foo>',
    '1234a',
    '"hello\\"',
    "'hello'",
    '42...',
    r'<barepath>',
    r'<barepath<char 1:3>>',
    r'"really\03weird"',
    r'"really\8weird"',
    "0x",
]


class TestArgListParserWorks(unittest.TestCase):
    def test_positive(self):
        for i, (input_string, expected) in enumerate(EXPECTATIONS):
            with self.subTest(i=i, input_string=input_string):
                tree = parse_arg.arg_list_parser.parse(input_string)
                try:
                    actual = parse_arg.TRANSFORMER.transform(tree)
                except:
                    print(f"{tree=}")
                    print(f"pretty:{tree.pretty()}")
                    raise
                self.assertEqual(actual, expected)

    def test_negative(self):
        exceptions = (
            lark.exceptions.UnexpectedCharacters,
            lark.exceptions.UnexpectedToken,
            lark.exceptions.UnexpectedEOF,
            lark.exceptions.VisitError,
        )
        for i, input_string in enumerate(NEGATIVES):
            with self.subTest(i=i, input_string=input_string):
                with self.assertRaises(exceptions):
                    tree = parse_arg.arg_list_parser.parse(input_string)
                    built = parse_arg.TRANSFORMER.transform(tree)
                    self.fail(f"{tree=} {built=}")


if __name__ == "__main__":
    unittest.main()
