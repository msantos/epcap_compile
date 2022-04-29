-module(lsf).
-export([f/0, f/1]).

f() ->
    case os:type() of
        {unix, linux} ->
            {ok, Fcode} = epcap_compile:compile("tcp and ( port 80 or port 443 )"),
            f(Fcode);
        _ ->
            {error, unsupported}
    end.

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
