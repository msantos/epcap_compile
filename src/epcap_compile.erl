%% Copyright (c) 2012-2015, Michael Santos <michael.santos@gmail.com>
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
-module(epcap_compile).

-export([
    compile/1, compile/2
    ]).

-define(PCAP_NETMASK_UNKNOWN, 16#ffffffff).
-define(DLT_EN10MB, 1).


-on_load(on_load/0).


on_load() ->
    erlang:load_nif(progname(), []).

-spec pcap_compile(
    Filter :: iodata(),
    Optimize :: 0 | 1,
    Netmask :: non_neg_integer(),
    Linktype :: integer(),
    Snaplen :: integer()) -> {ok, [binary()]} | {error, string()}.
pcap_compile(_,_,_,_,_) ->
    erlang:nif_error(not_implemented).

-spec compile(Filter :: iodata()) -> {ok, [binary()]} | {error, string()}.
compile(Filter) ->
    compile(Filter, []).

-type compile_options() :: [
        {optimize, true | false} |
        {netmask, non_neg_integer()} |
        {dlt, integer()} |
        {snaplen, integer()}
    ].
-spec compile(Filter :: iodata(), compile_options()) -> {ok, [binary()]} | {error, string()}.
compile(Filter, Options) when is_binary(Filter); is_list(Filter) ->
    Optimize = bool(proplists:get_value(optimize, Options, true)),
    Netmask = mask(proplists:get_value(netmask, Options, ?PCAP_NETMASK_UNKNOWN)),
    Linktype = proplists:get_value(dlt, Options, ?DLT_EN10MB),
    Snaplen = proplists:get_value(snaplen, Options, 16#ffff),

    pcap_compile(Filter, Optimize, Netmask, Linktype, Snaplen).

bool(true) -> 1;
bool(false) -> 0.

mask(N) when is_integer(N) -> N;
mask({A,B,C,D}) -> (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

progname() ->
    case code:priv_dir(?MODULE) of
        {error,bad_name} ->
            filename:join([
                filename:dirname(code:which(?MODULE)),
                    "..",
                    "priv",
                    ?MODULE
                ]);
        Dir ->
            filename:join([Dir,?MODULE])
    end.
