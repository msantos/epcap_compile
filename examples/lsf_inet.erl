%% Copyright (c) 2012, Michael Santos <michael.santos@gmail.com>
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
-module(lsf_inet).
-export([f/0]).

f() ->
    {ok, Fcode} = epcap_compile:compile("tcp and port 443"),
    unfiltered(Fcode),
    filtered(Fcode).


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
