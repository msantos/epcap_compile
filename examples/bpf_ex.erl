-module(bpf_ex).
-export([f/0, f/1, f/2]).

f() ->
    f("en1").

f(Dev) ->
    case os:type() of
        {unix, BSD} when
            BSD == darwin;
            BSD == freebsd;
            BSD == netbsd;
            BSD == openbsd
        ->
            f(Dev, "ip and ( src host 192.168.10.1 or dst host 192.168.10.1 )");
        _ ->
            {error, unsupported}
    end.

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
