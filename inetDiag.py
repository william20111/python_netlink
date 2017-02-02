import netlink
import io
import socket


def tcp_diag():
    payload = netlink.new_inet_diag_req({
        "family": netlink.AF_INET,
        "protocol": netlink.IPPROTO_TCP,
        "ext": 0,
        "pad": 0,
        "states": netlink.TCPF_ALL
        })
    hdr = netlink.sock_diag(payload, 178431)
    return hdr

tcp_payload_parser = netlink.parse_inet_diag_msg


def get_sock_diag(hdr, payload_parser):
    con = netlink.new_sock_diag()
    con.send(hdr)
    msgs = []
    goout = False
    while True:
        d = con.recv(65533)
        b = io.BytesIO(d)
        while True:
            if b.tell() >= len(d):
                break
            msg = netlink.parse_nlmsg(b)
            if msg["type"] == netlink.DONE:
                goout = True
                break
            elif msg["type"] == netlink.ERROR:
                raise ValueError(msg)
            mlen = b.tell() - 16 + msg["len"]
            payload = payload_parser(b)
            attrs = netlink.parse_attrs(b, mlen)
            msgs.append({
                "msg": msg,
                "payload": payload,
                "attrs": attrs
                })
        if goout:
            break
    b.close()
    return msgs

state_table = (
        "EMPTY SLOT",
        "ESTABLISHED",
        "SENT",
        "RECV",
        "WAIT1",
        "WAIT2",
        "WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING"
        )


def print_tcp(msgs):
    socket_state_table = {"EMPTY SLOT": 0, "ESTABLISHED": 0, "SENT": 0, "RECV": 0, "WAIT1": 0, "WAIT2": 0, "WAIT": 0,
                          "CLOSE": 0, "CLOSE_WAIT": 0, "LAST_ACK": 0, "LISTEN": 0, "CLOSING": 0
                          }
    for msg in msgs:
        msg_content = msg['payload']
        state = state_table[msg_content["state"]]
        socket_state_table[state] += 1
        print(msg)
#    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    for key, value in socket_state_table.items():
#        message = 'tcp.' + key.lower() + ':' + str(value) + '|g|#netlinkstat'
#        sock.sendto(bytes(message, 'utf-8'), ('127.0.0.1', 8125))


def main():
    msgs = get_sock_diag(tcp_diag(), tcp_payload_parser)
    print_tcp(msgs)

if __name__ == "__main__":
    main()
