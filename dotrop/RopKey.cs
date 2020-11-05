/**
 * Copyright (c) 2020 Janky <box@janky.tech>
 * All right reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using tech.janky.dotrop.rop;


namespace tech.janky.dotrop {

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopKey : RopObject {
    internal RopKey(RopBind own, RopHandle kid) {
        if(kid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.kid = kid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(kid != null) {
            ret = (int)lib.rnp_key_handle_destroy(kid);
            kid = null;
        }
        return ret;
    }

    public RopHandle getHandle() {
        return kid;
    }

    internal void Detach() {
        kid = null;
    }

    // API

    public string keyid() {
        int ret = (int)lib.rnp_key_get_keyid(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string alg() {
        int ret = (int)lib.rnp_key_get_alg(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string primary_grip() {
        int ret = (int)lib.rnp_key_get_primary_grip(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string fprint() {
        int ret = (int)lib.rnp_key_get_fprint(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string grip() {
        int ret = (int)lib.rnp_key_get_grip(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string primary_uid() {
        int ret = (int)lib.rnp_key_get_primary_uid(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string curve() {
        int ret = (int)lib.rnp_key_get_curve(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string revocation_reason() {
        int ret = (int)lib.rnp_key_get_revocation_reason(kid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public void set_expiration(TimeSpan expiry) {
        int ret = (int)lib.rnp_key_set_expiration(kid, (uint)Util.TimeDelta2Sec(expiry));
        Util.Return(ret);
    }
    public bool is_revoked() {
        int ret = (int)lib.rnp_key_is_revoked(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_superseded() {
        int ret = (int)lib.rnp_key_is_superseded(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_compromised() {
        int ret = (int)lib.rnp_key_is_compromised(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_retired() {
        int ret = (int)lib.rnp_key_is_retired(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_locked() {
        int ret = (int)lib.rnp_key_is_locked(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_protected() {
        int ret = (int)lib.rnp_key_is_protected(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_primary() {
        int ret = (int)lib.rnp_key_is_primary(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool is_sub() {
        int ret = (int)lib.rnp_key_is_sub(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool have_secret() {
        int ret = (int)lib.rnp_key_have_secret(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public bool have_public() {
        int ret = (int)lib.rnp_key_have_public(kid, out bool bl);
        return Util.PopBool(lib, bl, ret);
    }
    public DateTime creation() {
        int ret = (int)lib.rnp_key_get_creation(kid, out uint dt);
        return DateTimeOffset.FromUnixTimeSeconds(Util.PopLong(lib, (long)dt, ret)).LocalDateTime;
    }
    public TimeSpan expiration() {
        int ret = (int)lib.rnp_key_get_expiration(kid, out uint ex);
        return TimeSpan.FromSeconds(Util.PopLong(lib, (long)ex, ret));
    }
    public int uid_count() {
        int ret = (int)lib.rnp_key_get_uid_count(kid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public int signature_count() {
        int ret = (int)lib.rnp_key_get_signature_count(kid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public int bits() {
        int ret = (int)lib.rnp_key_get_bits(kid, out uint bt);
        return Util.PopInt(lib, (int)bt, ret);
    }
    public int dsa_qbits() {
        int ret = (int)lib.rnp_key_get_dsa_qbits(kid, out uint qb);
        return Util.PopInt(lib, (int)qb, ret);
    }
    public int subkey_count() {
        int ret = (int)lib.rnp_key_get_subkey_count(kid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public string get_uid_at(int idx) {
        int ret = (int)lib.rnp_key_get_uid_at(kid, (uint)idx, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public RopData to_json(bool publicMpis = true, bool secretMpis = true, bool signatures = true, bool signMpis = true) {
        int flags = (publicMpis? ROPD.RNP_JSON_PUBLIC_MPIS : 0);
        flags |= (secretMpis? ROPD.RNP_JSON_SECRET_MPIS : 0);
        flags |= (signatures? ROPD.RNP_JSON_SIGNATURES : 0);
        flags |= (signMpis? ROPD.RNP_JSON_SIGNATURE_MPIS : 0);
        int ret = (int)lib.rnp_key_to_json(kid, (uint)flags, out RopHandle js);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, js, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData packets_to_json(bool secret, bool mpi = true, bool raw = true, bool grip = true) {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = (int)lib.rnp_key_packets_to_json(kid, secret, (uint)flags, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public bool allows_usage(string usage) {
        int ret = (int)lib.rnp_key_allows_usage(kid, usage, out bool usg);
        return Util.PopBool(lib, usg, ret);
    }
    public bool allows_usages(string[] usages) {
        foreach(string usage in usages)
            if(!allows_usage(usage))
                return false;
        return true;
    }
    public bool disallows_usages(string[] usages) {
        foreach(string usage in usages)
            if(allows_usage(usage))
                return false;
        return true;
    }
    public void lock_() {
        int ret = (int)lib.rnp_key_lock(kid);
        Util.Return(ret);
    }
    public void unlock(string password) {
        int ret = (int)lib.rnp_key_unlock(kid, password);
        Util.Return(ret);
    }

    public RopUidHandle get_uid_handle_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_key_get_uid_handle_at(kid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopUidHandle uid = new RopUidHandle(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(uid, tag);
            return uid;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void protect(string password, string cipher, string cipherMode, string hash, int iterations) {
        int ret = (int)lib.rnp_key_protect(kid, password, cipher, cipherMode, hash, (uint)iterations);
        Util.Return(ret);
    }
    public void unprotect(String password) {
        int ret = (int)lib.rnp_key_unprotect(kid, password);
        Util.Return(ret);
    }
    public RopData public_key_data() {
        int ret = (int)lib.rnp_get_public_key_data(kid, out RopHandle hnd, out uint bl);
        long len = Util.PopLong(lib, (long)bl, ret);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), len);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData secret_key_data() {
        int ret = (int)lib.rnp_get_secret_key_data(kid, out RopHandle hnd, out uint bl);
        long len = Util.PopLong(lib, (long)bl, ret);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), len);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void add_uid(string uid, string hash, DateTime expiration, int keyFlags, bool primary) {
        int ret = (int)lib.rnp_key_add_uid(kid, uid, hash, (uint)Util.Datetime2TS(expiration), (uint)keyFlags, primary);
        Util.Return(ret);
    }
    public RopKey get_subkey_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_key_get_subkey_at(kid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopKey key = new RopKey(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(key, tag);
            return key;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopSign get_signature_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_key_get_signature_at(kid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopSign sign = new RopSign(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(sign, tag);
            return sign;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void export(RopOutput output, bool pub = true, bool sec = true, bool subkey = false, bool armored = false) {
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        int flags = (pub? ROPD.RNP_KEY_EXPORT_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_EXPORT_SECRET : 0);
        flags |= (subkey? ROPD.RNP_KEY_EXPORT_SUBKEYS : 0);
        flags |= (armored? ROPD.RNP_KEY_EXPORT_ARMORED : 0);
        int ret = (int)lib.rnp_key_export(kid, outp, (uint)flags);
        Util.Return(ret);
    }
    public void export_public(RopOutput output, bool subkey = false, bool armored = false) {
        export(output, true, false, subkey, armored);
    }
    public void export_secret(RopOutput output, bool subkey = false, bool armored = false) {
        export(output, false, true, subkey, armored);
    }
    public void remove(bool pub = false, bool sec = false, bool subkeys = false) {
        int flags = (pub? ROPD.RNP_KEY_REMOVE_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_REMOVE_SECRET : 0);
        flags |= (subkeys? ROPD.RNP_KEY_REMOVE_SUBKEYS : 0);
        int ret = (int)lib.rnp_key_remove(kid, (uint)flags);
        Util.Return(ret);
    }
    public void remove_public(bool subkeys = false) {
        remove(true, false, subkeys);
    }
    public void remove_secret(bool subkeys = false) {
        remove(false, true, subkeys);
    }
    public void export_revocation(RopOutput output, string hash, string code, string reason) {
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        int ret = (int)lib.rnp_key_export_revocation(kid, outp, 0, hash, code, reason);
        Util.Return(ret);
    }
    public void revoke(string hash, string code, string reason) {
        int ret = (int)lib.rnp_key_revoke(kid, 0, hash, code, reason);
        Util.Return(ret);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle kid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopUidHandle : RopObject {
    internal RopUidHandle(RopBind own, RopHandle huid) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.huid = huid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(huid != null) {
            ret = (int)lib.rnp_uid_handle_destroy(huid);
            huid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return huid;
    }
    
    // API

    public int signature_count() {
        int ret = (int)lib.rnp_uid_get_signature_count(huid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public bool is_revoked() {
        int ret = (int)lib.rnp_uid_is_revoked(huid, out bool rv);
        return Util.PopBool(lib, rv, ret);
    }
    public RopSign get_signature_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_uid_get_signature_at(huid, (uint)idx, out RopHandle sg);
        if(own.TryGetTarget(out RopBind bind)) {
            RopSign sign = new RopSign(bind, Util.PopHandle(lib, sg, ret));
            bind.PutObj(sign, tag);
            return sign;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle huid;
}

}
