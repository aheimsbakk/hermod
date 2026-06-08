# discovery problem

it looks like we do not populate with the information we have. if we do not have the information. why not? the server should alway manage to receive public ip. the public ip could be an ip on an internal address space. an advanced user with segmentet home network can have layers of nat and multiple private networks as me.

verify server, sender, receiver, and resolve the issue.

security by obscurity is not a valid point for these logs.

## sender

$  ./hermod-linux-arm64 --verbose debug tx test
time=2026-06-07T20:51:08.438+02:00 level=DEBUG msg="loading config"
time=2026-06-07T20:51:08.439+02:00 level=DEBUG msg="payload classified" kind=text name="" input=test
time=2026-06-07T20:51:08.440+02:00 level=DEBUG msg="transfer code generated" channel_id=4891 words=3
Transfer code: 4891-shush-entry-decaf
time=2026-06-07T20:51:08.440+02:00 level=DEBUG msg="checking pinned fingerprint for server" server=wss://proxy.lan:4376
time=2026-06-07T20:51:08.440+02:00 level=INFO msg="Connecting to signaling server" server=wss://proxy.lan:4376
time=2026-06-07T20:51:08.489+02:00 level=DEBUG msg="WebSocket connection to signaling server established"
time=2026-06-07T20:51:08.489+02:00 level=DEBUG msg="allocating channel on signaling server" channel_id=4891
time=2026-06-07T20:51:08.493+02:00 level=INFO msg="Channel allocated" channel_id=4891 public_ipv4="" public_ipv6=""
time=2026-06-07T20:51:08.493+02:00 level=DEBUG msg="generating ephemeral TLS certificate for QUIC"
time=2026-06-07T20:51:08.495+02:00 level=DEBUG msg="ephemeral certificate generated" fingerprint=c5d5e689b5657334ebf61d8b9d1881649aac5b44eb190a504323129304895fa7
time=2026-06-07T20:51:08.495+02:00 level=DEBUG msg="binding UDP socket" addr=:0
time=2026-06-07T20:51:08.497+02:00 level=DEBUG msg="UDP socket bound" local_addr=[::]:50816
time=2026-06-07T20:51:08.497+02:00 level=DEBUG msg="initialising CPace PAKE handshake" role=sender
time=2026-06-07T20:51:08.500+02:00 level=INFO msg="Waiting for receiver to join the channel"
time=2026-06-07T20:51:25.458+02:00 level=INFO msg="Receiver joined the channel"
time=2026-06-07T20:51:25.458+02:00 level=DEBUG msg="sending CPace public message to peer via relay"
time=2026-06-07T20:51:25.459+02:00 level=DEBUG msg="waiting for peer CPace public message from relay"
time=2026-06-07T20:51:25.467+02:00 level=DEBUG msg="peer CPace message received and decoded"
time=2026-06-07T20:51:25.467+02:00 level=DEBUG msg="completing CPace handshake to derive shared key"
time=2026-06-07T20:51:25.469+02:00 level=INFO msg="PAKE handshake complete — shared key established"
time=2026-06-07T20:51:25.470+02:00 level=DEBUG msg="local endpoints collected" local_v4=[100.115.92.26:50816] local_v6="[[fd00:bad:cafe:0:10c6:8dff:fe10:10a4]:50816 [2a02:fe1:4075:f00:10c6:8dff:fe10:10a4]:50816 [fe80::10c6:8dff:fe10:10a4]:50816]" public_v4="" public_v6=""
time=2026-06-07T20:51:25.471+02:00 level=DEBUG msg="endpoint bundle encrypted and sending to peer via relay"
time=2026-06-07T20:51:25.474+02:00 level=DEBUG msg="waiting for receiver endpoint bundle from relay"
time=2026-06-07T20:51:25.481+02:00 level=DEBUG msg="receiver endpoint bundle received" public_v4="" public_v6="" local_v4_count=1 local_v6_count=0 require_verify=false
time=2026-06-07T20:51:25.481+02:00 level=DEBUG msg="NAT candidates parsed" v4_count=1 v6_count=0
time=2026-06-07T20:51:25.481+02:00 level=INFO msg="Starting UDP hole punch" v4_candidates=1 v6_candidates=0
Establishing P2P connection...
time=2026-06-07T20:51:25.682+02:00 level=INFO msg="UDP hole punch succeeded" peer_addr=[2a02:fe1:4075:f00::132]:37475
time=2026-06-07T20:51:25.682+02:00 level=DEBUG msg="dialling QUIC connection to peer" peer_addr=[2a02:fe1:4075:f00::132]:37475
connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?. See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
time=2026-06-07T20:51:25.706+02:00 level=INFO msg="QUIC connection established" peer_addr=[2a02:fe1:4075:f00::132]:37475
time=2026-06-07T20:51:25.706+02:00 level=DEBUG msg="reading and hashing payload" kind=text name=""
time=2026-06-07T20:51:25.706+02:00 level=DEBUG msg="payload ready" kind=text size_bytes=4 sha256=""
time=2026-06-07T20:51:25.707+02:00 level=DEBUG msg="opening QUIC metadata stream (stream 0)"
time=2026-06-07T20:51:25.710+02:00 level=DEBUG msg="metadata sent" bytes=36
time=2026-06-07T20:51:25.710+02:00 level=DEBUG msg="opening QUIC payload stream (stream 1)"
time=2026-06-07T20:51:25.710+02:00 level=INFO msg="Sending payload" kind=text size_bytes=4
sending 100% [==================================================================================================================] ( 4/ 4 B, 4.4 kB/s)
time=2026-06-07T20:51:25.712+02:00 level=DEBUG msg="payload stream closed — all bytes sent" sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
time=2026-06-07T20:51:25.712+02:00 level=DEBUG msg="opening QUIC trailing hash stream (stream 2)"
time=2026-06-07T20:51:25.713+02:00 level=DEBUG msg="trailing hash sent" sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
time=2026-06-07T20:51:25.713+02:00 level=DEBUG msg="waiting for receiver acknowledgement"
time=2026-06-07T20:51:25.720+02:00 level=WARN msg="did not receive acknowledgement from receiver — transfer may still have succeeded" err="Application error 0x0 (remote): done"
time=2026-06-07T20:51:25.720+02:00 level=INFO msg="Transfer complete" kind=text size_bytes=4
Transfer complete.

Not populated public not populated:
time=2026-06-07T20:51:08.493+02:00 level=INFO msg="Channel allocated" channel_id=4891 public_ipv4="" public_ipv6=""

Not populated with public:
time=2026-06-07T20:51:25.481+02:00 level=DEBUG msg="receiver endpoint bundle received" public_v4="" public_v6="" local_v4_count=1 local_v6_count=0 require_verify=false
time=2026-06-07T20:51:25.470+02:00 level=DEBUG msg="local endpoints collected" local_v4=[100.115.92.26:50816] local_v6="[[fd00:bad:cafe:0:10c6:8dff:fe10:10a4]:50816 [2a02:fe1:4075:f00:10c6:8dff:fe10:10a4]:50816 [fe80::10c6:8dff:fe10:10a4]:50816]" public_v4="" public_v6=""


## rceiver

$  ./hermod-linux-amd64 --verbose debug -4 rx 4891-shush-entry-decaf
time=2026-06-07T20:51:25.408+02:00 level=DEBUG msg="loading config"
time=2026-06-07T20:51:25.409+02:00 level=DEBUG msg="parsing transfer code"
time=2026-06-07T20:51:25.409+02:00 level=DEBUG msg="transfer code parsed" channel_id=4891
time=2026-06-07T20:51:25.409+02:00 level=DEBUG msg="generating ephemeral TLS certificate for QUIC"
time=2026-06-07T20:51:25.410+02:00 level=DEBUG msg="ephemeral certificate generated" fingerprint=35701e2ad2d88436b9aad5e5882e315fbade90bbc232ea59cb196066126a2fc2
time=2026-06-07T20:51:25.410+02:00 level=DEBUG msg="checking pinned fingerprint for server" server=wss://proxy.lan:4376
time=2026-06-07T20:51:25.410+02:00 level=INFO msg="Connecting to signaling server" server=wss://proxy.lan:4376
time=2026-06-07T20:51:25.423+02:00 level=DEBUG msg="WebSocket connection to signaling server established"
time=2026-06-07T20:51:25.423+02:00 level=DEBUG msg="joining channel on signaling server" channel_id=4891
time=2026-06-07T20:51:25.424+02:00 level=INFO msg="Joined channel" channel_id=4891 public_ipv4="" public_ipv6=""
time=2026-06-07T20:51:25.424+02:00 level=DEBUG msg="binding UDP socket" addr=:0
time=2026-06-07T20:51:25.424+02:00 level=DEBUG msg="UDP socket bound" local_addr=[::]:37475
time=2026-06-07T20:51:25.424+02:00 level=DEBUG msg="initialising CPace PAKE handshake" role=receiver
time=2026-06-07T20:51:25.425+02:00 level=DEBUG msg="waiting for sender CPace public message from relay"
time=2026-06-07T20:51:25.430+02:00 level=DEBUG msg="sender CPace message received and decoded"
time=2026-06-07T20:51:25.430+02:00 level=DEBUG msg="sending CPace public message to peer via relay"
time=2026-06-07T20:51:25.431+02:00 level=DEBUG msg="completing CPace handshake to derive shared key"
time=2026-06-07T20:51:25.431+02:00 level=INFO msg="PAKE handshake complete — shared key established"
time=2026-06-07T20:51:25.431+02:00 level=DEBUG msg="waiting for sender endpoint bundle from relay"
time=2026-06-07T20:51:25.447+02:00 level=DEBUG msg="sender endpoint bundle received" public_v4="" public_v6="" local_v4_count=1 local_v6_count=3 require_verify=false
time=2026-06-07T20:51:25.447+02:00 level=DEBUG msg="local endpoints collected" local_v4=[192.168.1.142:37475] local_v6=[] public_v4="" public_v6=""
time=2026-06-07T20:51:25.448+02:00 level=DEBUG msg="endpoint bundle encrypted and sending to sender via relay"
time=2026-06-07T20:51:25.448+02:00 level=DEBUG msg="NAT candidates parsed" v4_count=1 v6_count=3
time=2026-06-07T20:51:25.448+02:00 level=INFO msg="Starting UDP hole punch" v4_candidates=1 v6_candidates=3
Establishing P2P connection...
time=2026-06-07T20:51:25.655+02:00 level=INFO msg="UDP hole punch succeeded" peer_addr=[2a02:fe1:4075:f00:10c6:8dff:fe10:10a4]:50816
time=2026-06-07T20:51:25.655+02:00 level=DEBUG msg="starting QUIC listener for incoming sender connection"
connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?. See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
time=2026-06-07T20:51:25.655+02:00 level=DEBUG msg="waiting for sender to establish QUIC connection"
time=2026-06-07T20:51:25.678+02:00 level=INFO msg="QUIC connection accepted from sender"
time=2026-06-07T20:51:25.678+02:00 level=DEBUG msg="waiting for metadata stream from sender (stream 0)"
time=2026-06-07T20:51:25.681+02:00 level=INFO msg="Metadata received" kind=text name="" size_bytes=4
time=2026-06-07T20:51:25.681+02:00 level=DEBUG msg="metadata detail" sha256=""
time=2026-06-07T20:51:25.681+02:00 level=DEBUG msg="waiting for payload stream from sender (stream 1)"
time=2026-06-07T20:51:25.683+02:00 level=INFO msg="Receiving payload" kind=text size_bytes=4
test
time=2026-06-07T20:51:25.683+02:00 level=DEBUG msg="text payload written to stdout" size_bytes=4
time=2026-06-07T20:51:25.683+02:00 level=DEBUG msg="waiting for trailing hash stream from sender (stream 2)"
time=2026-06-07T20:51:25.686+02:00 level=DEBUG msg="trailing hash received" sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
time=2026-06-07T20:51:25.686+02:00 level=DEBUG msg="integrity check passed via trailing hash" sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
time=2026-06-07T20:51:25.686+02:00 level=DEBUG msg="sending acknowledgement to sender"
time=2026-06-07T20:51:25.686+02:00 level=DEBUG msg="acknowledgement sent"
time=2026-06-07T20:51:25.686+02:00 level=INFO msg="Transfer complete" kind=text size_bytes=4
Receive and verification complete.

Not populated public:
time=2026-06-07T20:51:25.424+02:00 level=INFO msg="Joined channel" channel_id=4891 public_ipv4="" public_ipv6=""

Not populated public:
time=2026-06-07T20:51:25.447+02:00 level=DEBUG msg="sender endpoint bundle received" public_v4="" public_v6="" local_v4_count=1 local_v6_count=3 require_verify=false
time=2026-06-07T20:51:25.447+02:00 level=DEBUG msg="local endpoints collected" local_v4=[192.168.1.142:37475] local_v6=[] public_v4="" public_v6=""

