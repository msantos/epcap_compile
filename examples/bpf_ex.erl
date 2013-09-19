%% Copyright (c) 2012-2013, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(bpf_ex).
-export([f/0, f/1, f/2]).

f() ->
    f("en1").

f(Dev) ->
    case os:type() of
        {unix, BSD} when BSD == darwin;
                BSD == freebsd;
                BSD == netbsd;
                BSD == openbsd ->
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
