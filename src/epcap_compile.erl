%%% @copyright 2012-2023 Michael Santos <michael.santos@gmail.com>

%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from
%%% this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%%% HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
%%% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
%%% PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-module(epcap_compile).

-export([
    compile/1,
    compile/2
]).

-define(PCAP_NETMASK_UNKNOWN, 16#ffffffff).

-define(DLT_EN10MB, 1).

-on_load(on_load/0).

on_load() ->
    erlang:load_nif(progname(), []).

-spec pcap_compile(
    Filter :: iodata(),
    Optimize :: 0 | 1,
    Netmask :: non_neg_integer() | {byte(), byte(), byte(), byte()},
    Linktype :: integer(),
    Snaplen :: integer()
) -> {ok, [binary()]} | {error, string()}.
pcap_compile(_, _, _, _, _) ->
    erlang:nif_error(not_implemented).

% @doc Compile a PCAP filter to a BPF program
%
% Filter is a string in pcap-filter(7) format.
%
% compile/1 defaults to:
%
% * optimization enabled
%
% * an unspecified netmask (filters specifying the broadcast
%   will return an error)
%
% * datalinktype set to ethernet (DLT_EN10MB)
%
% * a packet length of 65535 bytes
%
% * a limit of 8192 bytes for filters. Filters larger than this limit
%   will return `{error, enomem}'. A limit less than 0 disables the
%   length check.
%
% == Examples ==
%
% ```
% 1> epcap_compile:compile("ip and ( src host 192.168.10.1 or dst host 192.168.10.
% 1 )").
% {ok,[<<40,0,0,0,12,0,0,0>>,
%      <<21,0,0,5,0,8,0,0>>,
%      <<32,0,0,0,26,0,0,0>>,
%      <<21,0,2,0,1,10,168,192>>,
%      <<32,0,0,0,30,0,0,0>>,
%      <<21,0,0,1,1,10,168,192>>,
%      <<6,0,0,0,255,255,0,0>>,
%      <<6,0,0,0,0,0,0,0>>]}
% '''
-spec compile(Filter :: iodata()) -> {ok, [binary()]} | {error, string()}.
compile(Filter) ->
    compile(Filter, []).

-type compile_options() :: [
    {optimize, true | false}
    | {netmask, non_neg_integer()}
    | {dlt, integer()}
    | {snaplen, integer()}
    | {limit, integer()}
].

% @doc Compile a PCAP filter to a BPF program
%
% Filter is a string in pcap-filter(7) format.
%
% See pcap_compile(3PCAP) for documentation about each option.
-spec compile(Filter :: iodata(), compile_options()) -> {ok, [binary()]} | {error, string()}.
compile(Filter, Options) when is_binary(Filter); is_list(Filter) ->
    Optimize = bool(proplists:get_value(optimize, Options, true)),
    Netmask = mask(proplists:get_value(netmask, Options, ?PCAP_NETMASK_UNKNOWN)),
    Linktype = proplists:get_value(dlt, Options, ?DLT_EN10MB),
    Snaplen = proplists:get_value(snaplen, Options, 16#ffff),
    Limit = proplists:get_value(limit, Options, 8192),

    case iolist_size(Filter) < Limit orelse Limit < 0 of
        true ->
            pcap_compile(Filter, Optimize, Netmask, Linktype, Snaplen);
        false ->
            {error, enomem}
    end.

bool(true) -> 1;
bool(false) -> 0.

mask(N) when is_integer(N) -> N;
mask({A, B, C, D}) -> (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

progname() ->
    case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            filename:join([
                filename:dirname(code:which(?MODULE)),
                "..",
                "priv",
                ?MODULE
            ]);
        Dir ->
            filename:join([Dir, ?MODULE])
    end.
