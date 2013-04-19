/* Copyright (c) 2012-2013, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <pcap.h>
#include <string.h>
#include "erl_nif.h"


static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_enomem;


    static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_enomem = enif_make_atom(env, "enomem");

    return 0;
}

    static int
reload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

    static int
upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

    void
unload(ErlNifEnv* env, void* priv_data)
{
}

    static ERL_NIF_TERM
nif_pcap_compile(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary filter = {0};
    int optimize = 0;
    u_int32_t netmask = 0;
    int linktype = 0;
    int snaplen = 0;

    pcap_t *p = NULL;
    struct bpf_program fp = {0};

    int i = 0;
    ERL_NIF_TERM insns = {0};
    ERL_NIF_TERM res = {0};


    if (!enif_inspect_iolist_as_binary(env, argv[0], &filter))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[1], &optimize))
        return enif_make_badarg(env);

    if (!enif_get_uint(env, argv[2], &netmask))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[3], &linktype))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[4], &snaplen))
        return enif_make_badarg(env);

    /* NULL terminate the filter */
    if (!enif_realloc_binary(&filter, filter.size+1))
        return enif_make_tuple2(env, atom_error, atom_enomem);

    filter.data[filter.size-1] = '\0';

    p = pcap_open_dead(linktype, snaplen);

    if (p == NULL)
        return enif_make_tuple2(env, atom_error, atom_enomem);

    if (pcap_compile(p, &fp, (const char *)filter.data,
                optimize, netmask) != 0) {
        res = enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(p), ERL_NIF_LATIN1));
        goto ERR;
    }

    insns = enif_make_list(env, 0);
    
    /* Build the list from the end of the buffer, so the list does
     * not need to be reversed. */
    for (i = fp.bf_len-1; i >= 0; i--) {
        ErlNifBinary fcode = {0};

        if (!enif_alloc_binary(sizeof(struct bpf_insn), &fcode)) {
            res = enif_make_tuple2(env, atom_error, atom_enomem);
            goto ERR;
        }

        (void)memcpy(fcode.data, fp.bf_insns+i, fcode.size);
        insns = enif_make_list_cell(env, enif_make_binary(env, &fcode), insns);
    }

    res = enif_make_tuple2(env, atom_ok, insns);

ERR:
    pcap_close(p);

    return res;
}


static ErlNifFunc nif_funcs[] = {
    {"pcap_compile", 5, nif_pcap_compile},
};

ERL_NIF_INIT(epcap_compile, nif_funcs, load, reload, upgrade, unload)
