"""Independent parent privilege and private-route gate for the fixed profile."""
import ipaddress

BOOTSTRAP = r'''
import os,socket,struct
def attr(kind,data):
    size=4+len(data)
    return struct.pack('=HH',size,kind)+data+b'\0'*((-size)%4)
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0) as netlink:
    netlink.settimeout(2);netlink.bind((0,0))
    seq=0
    def request(kind,payload):
        global seq
        seq+=1
        packet=struct.pack('=IHHII',16+len(payload),kind,0x605,seq,0)+payload
        netlink.sendto(packet,(0,0))
        reply=netlink.recv(8192)
        length,message,flags,received,pid=struct.unpack_from('=IHHII',reply)
        if length<20 or message!=2 or received!=seq:raise RuntimeError('invalid netlink ack')
        error=struct.unpack_from('=i',reply,16)[0]
        if error:raise OSError(-error,'private netns setup refused')
    request(16,struct.pack('=BBHiII',0,0,0,0,1,1)
        +attr(3,b'swe-dummy\0')+attr(18|0x8000,attr(1,b'dummy\0')))
    index=socket.if_nametoindex('swe-dummy')
    source=socket.inet_aton('10.255.255.254');target=socket.inet_aton('10.255.255.1')
    request(20,struct.pack('=BBBBI',2,32,128,0,index)+attr(1,source)+attr(2,source))
    request(24,struct.pack('=BBBBBBBBI',2,32,0,0,254,4,253,1,0)
        +attr(1,target)+attr(4,struct.pack('=I',index))+attr(7,source))
# The privileged socket is closed before the final process is exec'd. Foreign
# repository code is never run in this author-only probe or bootstrap.
os.execve('/usr/bin/setpriv',['setpriv','--no-new-privs','--bounding-set=-all',
    '--inh-caps=-all','--ambient-caps=-all','--reuid=65534','--regid=65534','--clear-groups',
    '/opt/miniconda3/envs/testbed/bin/python','-I','-S','-B','/trusted/probe.py'],
    {'PATH':'/usr/bin:/bin','HOME':'/tmp','PYTHONDONTWRITEBYTECODE':'1'})
'''

CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')


def status_ok(text):
    facts = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    return (all(facts[k].split() == ['65534'] * 4 for k in ('Uid', 'Gid'))
        and not facts['Groups'].strip() and facts['NoNewPrivs'].strip() == '1'
        and all(int(facts[k], 16) == 0 for k in CAPS))


def routes_ok(ipv4, ipv6, interfaces):
    rows = [line.split() for line in ipv4.splitlines()[1:]]
    if (set(interfaces.split()) != {'lo', 'swe-dummy'} or len(rows) != 1
            or len(rows[0]) != 11
            or rows[0][0] != 'swe-dummy' or rows[0][1] != '01FFFF0A'
            or rows[0][2] != '00000000' or rows[0][7] != 'FFFFFFFF'
            or int(rows[0][3],16) != 5):
        return False
    for line in ipv6.splitlines():
        fields = line.split()
        if len(fields) != 10: return False
        destination, prefix, flags = fields[0], int(fields[1], 16), int(fields[8], 16)
        if fields[-1] == 'lo':
            if not (flags & 0x200 or destination == '0'*31+'1' and prefix == 128): return False
        elif fields[-1] == 'swe-dummy':
            # Kernel-created link-local/local and multicast routes lead only
            # to the peerless dummy sink, never a global/default IPv6 route.
            address = ipaddress.IPv6Address(int(destination,16))
            if not (fields[4] == '0'*32 and (address.is_link_local and prefix in (64,128)
                    or address.is_multicast and prefix == 8)): return False
        else: return False
    return True
