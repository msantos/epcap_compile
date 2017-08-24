%% Copyright (c) 2012-2017, Michael Santos <michael.santos@gmail.com>
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
-module(epcap_compile_SUITE).
-include_lib("common_test/include/ct.hrl").

-export([
        all/0
    ]).
-export([
        compile/1,
        compile_linktype/1,
        error_filter/1,
        large_filter1/1,
        large_filter2/1
    ]).

all() ->
    [compile, compile_linktype, error_filter, large_filter1, large_filter2].

compile(_Config) ->
    {ok,[<<40,0,0,0,12,0,0,0>>,
         <<21,0,0,5,0,8,0,0>>,
         <<32,0,0,0,26,0,0,0>>,
         <<21,0,2,0,1,10,168,192>>,
         <<32,0,0,0,30,0,0,0>>,
         <<21,0,0,1,1,10,168,192>>,
         <<6,0,0,0,255,255,0,0>>,
         <<6,0,0,0,0,0,0,0>>]} = epcap_compile:compile(
            "ip and ( src host 192.168.10.1 or dst host 192.168.10.1 )"
            ).

compile_linktype(_Config) ->
    DLT_SLIP = 8,
    Filter = "inbound or ( outbound and portrange 40000-41000 )",

    Result = {ok,[<<48,0,0,0,0,0,0,0>>,
         <<21,0,25,0,0,0,0,0>>,
         <<84,0,0,0,240,0,0,0>>,
         <<21,0,0,9,96,0,0,0>>,
         <<48,0,0,0,22,0,0,0>>,
         <<21,0,2,0,132,0,0,0>>,
         <<21,0,1,0,6,0,0,0>>,
         <<21,0,0,20,17,0,0,0>>,
         <<40,0,0,0,56,0,0,0>>,
         <<53,0,0,1,64,156,0,0>>,
         <<37,0,0,16,40,160,0,0>>,
         <<40,0,0,0,58,0,0,0>>,
         <<53,0,13,15,64,156,0,0>>,
         <<21,0,0,14,64,0,0,0>>,
         <<48,0,0,0,25,0,0,0>>,
         <<21,0,2,0,132,0,0,0>>,
         <<21,0,1,0,6,0,0,0>>,
         <<21,0,0,10,17,0,0,0>>,
         <<40,0,0,0,22,0,0,0>>,
         <<69,0,8,0,255,31,0,0>>,
         <<177,0,0,0,16,0,0,0>>,
         <<72,0,0,0,16,0,0,0>>,
         <<53,0,0,1,64,156,0,0>>,
         <<37,0,0,3,40,160,0,0>>,
         <<72,0,0,0,18,0,0,0>>,
         <<53,0,0,2,64,156,0,0>>,
         <<37,0,1,0,40,160,0,0>>,
         <<6,0,0,0,255,255,0,0>>,
         <<6,0,0,0,0,0,0,0>>]},

    Result = epcap_compile:compile(Filter, [{dlt, DLT_SLIP}]).

error_filter(_Config) ->
    Filter = "ip and ",
    {error, Error} = epcap_compile:compile(Filter),
    true = is_list(Error),
    ok.

large_filter1(_Config) ->
    Filter = string:copies("ip and not ", 50000),
    {error, Error} = epcap_compile:compile(Filter, [{limit, -1}]),
    true = is_list(Error),
    ok.

large_filter2(_Config) ->
    Filter = string:copies("ip and ", 50000) ++ "ip",
    {error, enomem} = epcap_compile:compile(Filter),
    ok.
