import socket
import struct
import io

NETLINK_SOCK_DIAG = 4
AF_INET = 2
AF_INET6 = 10
AF_NETLINK = 16
IPPROTO_TCP = 6
TCPF_ALL = 0xfff
F_REQUEST = 1
F_ROOT = 0x100
F_MATCH = 0x200
F_DUMP = F_ROOT | F_MATCH
ERROR = 0x2
DONE = 0x3
SOCK_DIAG_BY_FAMILY = 20


def parse_struct(b, fmt): 
    d = {}
    fmts = "".join([x[1] for x in fmt])
    raw = b.read(struct.calcsize(fmts)) 
    raw = struct.unpack(fmts, raw)   
    for i, item in enumerate(fmt):
        d[item[0]] = raw[i]
    return d 


def new_struct(d, fmt): 
    l = []
    fmts = "".join([x[1] for x in fmt]) 
    for i in fmt:    
        l.append(d[i[0]])
    return struct.pack(fmts, *l) 


def new_conn(proto): 
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, proto) 
    s.bind((0, 0))
    return s

nlmsg = ( 
        ("len", "I"),
        ("type", "H"),
        ("flags", "H"),
        ("seq", "I"), 
        ("pid", "I")
    ) 


def new_nlmsg(tp,  payload, seq, flags=F_REQUEST, pid=0):
    return new_struct({
        "len": 16 + len(payload),
        "type": tp,
        "flags": flags,
        "seq": seq,
        "pid": pid
        }, nlmsg) + payload


def parse_nlmsg(b):
    return parse_struct(b, nlmsg) 

nlattr = (
        ("len", "H"),
        ("type", "H")
        )


def parse_nlattr(b):
    at = parse_struct(b, nlattr)
    at["payload"] = b.read(at["len"] - 4)
    mark = b.tell()
    if mark % 4:
        b.seek(4 - (mark % 4), io.SEEK_CUR)
    return at


def parse_nested(attr):
    b = io.StringIO(attr["payload"])
    tlen = attr["len"] - 4
    attrs = []
    while b.tell() < tlen:
        attr = parse_nlattr(b)
        attrs.append(attr)
    b.close()
    return attrs


def parse_attrs(b, mlen):
    attrs = []
    while b.tell() < mlen:
        attr = parse_nlattr(b)
        attrs.append(attr)
    return attrs


netlink_diag_req = (
        ("family", "B"),
        ("protocol", "B"),
        ("pad", "H"),
        ("ino", "I"),
        ("show", "I"),
        ("cookie", "Q")
        )

def new_netlink_diag_req(d):
    return new_struct(d, netlink_diag_req)


def parse_netlink_diag_req(b):
    return parse_struct(b, netlink_diag_req)


netlink_diag_msg = (
        ("family", "B"),
        ("type", "B"),
        ("protocol", "B"), 
        ("state", "B"),
        ("portid", "I"),
        ("dst_portid", "I"),
        ("dst_group", "I"),
        ("ino", "I"),
        ("cookie0", "I"),
        ("cookie1", "I")
        )


def new_netlink_diag_msg(d):
    return new_struct(d, netlink_diag_msg)


def parse_netlink_diag_msg(b):
    return parse_struct(b, netlink_diag_msg)

diag_req_v2 = ( 
        ("family", "B"),
        ("protocol", "B"),
        ("ext", "B"),
        ("pad", "B"),
        ("states", "I")
        )


def new_inet_diag_req(d):
    return new_struct(d, diag_req_v2) + new_sockid({
        "sport": 0,
        "dport": 0,
        "src": (0, 0, 0, 0),
        "dst": (0, 0, 0, 0),
        "if": 0,
        "cookie": (0, 0)
        })

diag_sockid = (
        ("sport", ">H"),
        ("dport", ">H"),
        ("src", ">IIII"),
        ("dst", ">IIII"),
        ("if", "I"),
        ("cookie", "II") 
        ) 


def new_sockid(d):
    l = []
    l.append(struct.pack(diag_sockid[0][1], d["sport"]))
    l.append(struct.pack(diag_sockid[1][1], d["dport"]))
    l.append(struct.pack(diag_sockid[2][1], *d["src"]))
    l.append(struct.pack(diag_sockid[3][1], *d["dst"]))
    l.append(struct.pack(diag_sockid[4][1], d["if"]))
    l.append(struct.pack(diag_sockid[5][1], *d["cookie"]))
    return b"".join(l)
        

def parse_sockid(b):
    sport = struct.unpack(">H", b.read(2))[0]
    dport = struct.unpack(">H", b.read(2))[0]
    src = struct.unpack(">IIII", b.read(16))
    dst = struct.unpack(">IIII", b.read(16))
    if_ = struct.unpack("I", b.read(4))[0]
    cookie = struct.unpack("II", b.read(8))
    return {
        "sport": sport,
        "dport": dport,
        "src": src,
        "dst": dst,
        "if": if_,
        "cookie": cookie,
            } 
    

inet_diag_msg_top_half = (
        ("family", "B"),
        ("state", "B"),
        ("timer", "B"),
        ("retrans", "B")
        )

inet_diag_msg_bottom_half = (
        ("expires", "I"),
        ("rqueue", "I"),
        ("wqueue", "I"),
        ("uid", "I"),
        ("iode", "I")
        ) 


def new_inet_diag_msg(d):
    return new_struct(d, inet_diag_msg_top_half) + new_sockid(d) + new_struct(d, inet_diag_msg_bottom_half)


def parse_inet_diag_msg(b): 
    d = {}
    d.update(parse_struct(b, inet_diag_msg_top_half))
    d.update(parse_sockid(b))
    d.update(parse_struct(b, inet_diag_msg_bottom_half))
    return d


def new_sock_diag():
    return new_conn(NETLINK_SOCK_DIAG)


def sock_diag(payload, seq): 
    hdr = new_nlmsg(SOCK_DIAG_BY_FAMILY, payload, seq, flags=(F_REQUEST|F_DUMP))
    return hdr
