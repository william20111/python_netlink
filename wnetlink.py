import socket

path = '/proc/net/sockstat'

with open(path,'r') as f:
    stats = f.read()
    stats_list = stats.split('\n')
    tcp = stats_list[1].split(' ')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = 'tcp.' + tcp[1].lower() + ':' + tcp[2] + '|g|#sockdiag'
    sock.sendto(bytes(message, 'utf-8'), ('127.0.0.1', 8125))
    message = 'tcp.' + tcp[5].lower() + ':' + tcp[6] + '|g|#sockdiag'

