epcap\_compile is an Erlang library for compiling PCAP filters to BPF
programs (see pcap-filter(7)).

epcap\_compile uses the NIF interface to wrap pcap\_compile(3PCAP)
from libpcap.


## WARNING

Since the library passes the filter string to pcap\_compile(3PCAP)
directly, any bugs in pcap\_compile() may cause the Erlang VM to crash. Do
not use filters from untrusted sources.

Also note very large filters may block the scheduler. For example:

    epcap_compile:compile(string:copies("ip and ", 50000) ++ "ip").


## REQUIREMENTS

* libpcap

  On Ubuntu: sudo apt-get install libpcap-dev

These libraries are not required but can be used with epcap\_compile:

* pkt: https://github.com/msantos/pkt.git

  Use pkt to map the datalinktype to a number:

        pkt:dlt(en10mb)

* procket: https://github.com/msantos/procket.git

  Set a BPF filter on any kind of socket (Linux) or on a BPF device
  (BSD).


## COMPILING

    rebar3 compile


## EXPORTS

    compile(Filter) -> {ok, Fcode} | {error, Error}
    compile(Filter, Options) -> {ok, Fcode} | {error, Error}

        Types   Filter = string() | binary()
                Fcode = [ Insn ]
                Insn = binary()
                Error = enomem | string()
                Options = [ Option ]
                Option = {optimize, boolean()}
                    | {netmask, IPaddr}
                    | {dlt, integer()}
                    | {snaplen, integer()}

        Filter is a string in pcap-filter(7) format.

        If the PCAP filter is successfully compiled to a BPF program,
        a list of BPF instructions is returned.

        If an error occurs, a string describing the error is returned
        to the caller.

        compile/1 defaults to:

            * optimization enabled

            * an unspecified netmask (filters specifying the broadcast
              will return an error)

            * datalinktype set to ethernet (DLT_EN10MB)

            * a packet length of 65535 bytes

        See pcap_compile(3PCAP) for information about each of these options.


## EXAMPLES

### Compile a PCAP Filter

    $ erl -pa ebin
    1> epcap_compile:compile("ip and ( src host 192.168.10.1 or dst host 192.168.10.1 )").
    {ok,[<<40,0,0,0,12,0,0,0>>,
         <<21,0,0,5,0,8,0,0>>,
         <<32,0,0,0,26,0,0,0>>,
         <<21,0,2,0,1,10,168,192>>,
         <<32,0,0,0,30,0,0,0>>,
         <<21,0,0,1,1,10,168,192>>,
         <<6,0,0,0,255,255,0,0>>,
         <<6,0,0,0,0,0,0,0>>]}

The same BPF program can be generated from Erlang by using the bpf module in procket:

    ip({A,B,C,D}) ->
        IP = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,

        [
            % Ethernet
            ?BPF_STMT(?BPF_LD+?BPF_H+?BPF_ABS, 12),                     % offset = Ethernet Type
            ?BPF_JUMP(?BPF_JMP+?BPF_JEQ+?BPF_K, ?ETHERTYPE_IP, 0, 5),   % type = IP

            % IP
            ?BPF_STMT(?BPF_LD+?BPF_W+?BPF_ABS, 26),                     % offset = Source IP address
            ?BPF_JUMP(?BPF_JMP+?BPF_JEQ+?BPF_K, IP, 2, 0),              % source = {A,B,C,D}
            ?BPF_STMT(?BPF_LD+?BPF_W+?BPF_ABS, 30),                     % offset = Destination IP address
            ?BPF_JUMP(?BPF_JMP+?BPF_JEQ+?BPF_K, IP, 0, 1),              % destination = {A,B,C,D}

            % Amount of packet to return
            ?BPF_STMT(?BPF_RET+?BPF_K, 16#FFFFFFFF),                    % Return up to 2^32-1 bytes
            ?BPF_STMT(?BPF_RET+?BPF_K, 0)                               % Return 0 bytes: drop packet
        ].


### Apply a BPF Filter to a PF\_PACKET Socket (Linux)

    -module(lsf).
    -export([f/0, f/1]).

    f() ->
        {ok, Fcode} = epcap_compile:compile("tcp and ( port 80 or port 443 )"),
        f(Fcode).

    f(Fcode) when is_list(Fcode) ->
        {ok, S} = packet:socket(),
        {ok, _} = packet:filter(S, Fcode),

        loop(S).

    loop(S) ->
        case procket:recv(S, 1500) of
            {ok, Data} ->
                error_logger:info_report(Data),
                loop(S);
            {error, eagain} ->
                timer:sleep(10),
                loop(S)
        end.

### Apply a BPF Filter to a TCP Socket (Linux)

    -module(lsf_inet).
    -export([f/0]).

    f() ->
        {ok, Fcode} = epcap_compile:compile("tcp and port 443"),
        unfiltered(Fcode),
        filtered(Fcode).

    unfiltered(Fcode) when is_list(Fcode) ->
        {ok, S} = gen_tcp:connect("www.google.com", 80,
                [binary, {packet, 0}, {active, false}]),

        ok = gen_tcp:send(S, "GET / HTTP/1.0\r\n\r\n"),
        {ok, R} = gen_tcp:recv(S, 0, 5000),
        error_logger:info_report([{unfiltered, R}]),
        ok = gen_tcp:close(S).

    filtered(Fcode) when is_list(Fcode) ->
        {ok, S} = gen_tcp:connect("www.google.com", 80,
                [binary, {packet, 0}, {active, false}]),

        {ok, FD} = inet:getfd(S),
        {ok, _} = packet:filter(FD, Fcode),

        ok = gen_tcp:send(S, "GET / HTTP/1.0\r\n\r\n"),
        {error, timeout} = gen_tcp:recv(S, 0, 5000),
        error_logger:info_report([{filtered, "connection timeout"}]),

        ok = gen_tcp:close(S).

### Applying a BPF Filter on BSD


    -module(bpf_ex).
    -export([f/1, f/2]).

    f(Dev) ->
        f(Dev, "ip and ( src host 192.168.10.1 or dst host 192.168.10.1 )").

    f(Dev, Filter) ->
        {ok, Socket, Length} = bpf:open(Dev),
        {ok, Fcode} = epcap_compile:compile(Filter),
        {ok, _} = bpf:ctl(Socket, setf, Fcode),
        loop(Socket, Length).

    loop(Socket, Length) ->
        case procket:read(Socket, Length) of
            {ok, <<>>} ->
                loop(Socket, Length);
            {ok, Data} ->
                {bpf_buf, Time, Datalen, Packet, Rest} = bpf:buf(Data),
                error_logger:info_report([
                    {time, Time},
                    {packet_is_truncated, Datalen /= byte_size(Packet)},
                    {packet, Packet},
                    {packet_size, byte_size(Packet)},
                    {remaining, byte_size(Rest)}
                ]),
                loop(Socket, Length);
            {error, eagain} ->
                timer:sleep(10),
                loop(Socket, Length)
        end.
