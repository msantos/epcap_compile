-module(lsf_inet).
-export([f/0]).

f() ->
    case os:type() of
        {unix, linux} ->
            {ok, Fcode} = epcap_compile:compile("tcp and port 443"),
            unfiltered(Fcode),
            filtered(Fcode);
        _ ->
            {error, unsupported}
    end.

unfiltered(Fcode) when is_list(Fcode) ->
    {ok, S} = gen_tcp:connect("www.google.com", 80, [
        binary,
        {packet, 0},
        {active, false}
    ]),

    ok = gen_tcp:send(S, "GET / HTTP/1.0\r\n\r\n"),
    {ok, R} = gen_tcp:recv(S, 0, 5000),
    error_logger:info_report([{unfiltered, R}]),
    ok = gen_tcp:close(S).

filtered(Fcode) when is_list(Fcode) ->
    {ok, S} = gen_tcp:connect("www.google.com", 80, [
        binary,
        {packet, 0},
        {active, false}
    ]),

    {ok, FD} = inet:getfd(S),
    {ok, _} = packet:filter(FD, Fcode),

    ok = gen_tcp:send(S, "GET /test HTTP/1.0\r\n\r\n"),
    {error, timeout} = gen_tcp:recv(S, 0, 5000),
    error_logger:info_report([{filtered, "connection timeout"}]),
    ok = gen_tcp:close(S).
