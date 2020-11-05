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
public class RopSign : RopObject {
    internal RopSign(RopBind own, RopHandle sgid) {
        if(sgid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sgid = sgid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(sgid != null) {
            ret = (int)lib.rnp_signature_handle_destroy(sgid);
            sgid = null;
        }
        return ret;
    }

    public RopHandle getHandle() {
        return sgid;
    }

    // API

    public string alg() {
        int ret = (int)lib.rnp_signature_get_alg(sgid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string hash_alg() {
        int ret = (int)lib.rnp_signature_get_hash_alg(sgid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public DateTime creation() {
        int ret = (int)lib.rnp_signature_get_creation(sgid, out uint cr);
        return DateTimeOffset.FromUnixTimeSeconds(Util.PopLong(lib, (long)cr, ret)).LocalDateTime;
    }
    public String keyid() {
        int ret = (int)lib.rnp_signature_get_keyid(sgid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public RopKey get_signer(int tag = 0) {
        int ret = (int)lib.rnp_signature_get_signer(sgid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopKey key = new RopKey(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(key, tag);
            return key;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData to_json(bool mpi = false, bool raw = false, bool grip = false) {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = (int)lib.rnp_signature_packet_to_json(sgid, (uint)flags, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sgid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopSignSignature {
    public RopSignSignature(RopBind own, RopHandle sgid) {
        if(sgid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.lib = own.getLib();
        this.sgid = sgid;
    }

    public RopHandle getHandle() {
        return sgid;
    }

    // API
    
    public void set_hash(string hash) {
        int ret = (int)lib.rnp_op_sign_signature_set_hash(sgid, hash);
        Util.Return(ret);
    }
    public void set_creation_time(DateTime create) {
        int ret = (int)lib.rnp_op_sign_signature_set_creation_time(sgid, (uint)Util.Datetime2TS(create));
        Util.Return(ret);
    }
    public void set_expiration_time(DateTime expires) {
        int ret = (int)lib.rnp_op_sign_signature_set_expiration_time(sgid, (uint)Util.Datetime2TS(expires));
        Util.Return(ret);
    }
    
    private RopLib lib;
    private RopHandle sgid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopVeriSignature {
    public RopVeriSignature(RopBind own, RopHandle sgid) {
        if(sgid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sgid = sgid;
    }

    public RopHandle getHandle() {
        return sgid;
    }

    // API

    public string hash() {
        int ret = (int)lib.rnp_op_verify_signature_get_hash(sgid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public int status() {
        return (int)lib.rnp_op_verify_signature_get_status(sgid);
    }
    public RopSign get_handle(int tag = 0) {
        int ret = (int)lib.rnp_op_verify_signature_get_handle(sgid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopSign sign = new RopSign(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(sign, tag);
            return sign;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopKey get_key(int tag = 0) {
        int ret = (int)lib.rnp_op_verify_signature_get_key(sgid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopKey key = new RopKey(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(key, tag);
            return key;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public DateTime[] get_times() {
        int ret = (int)lib.rnp_op_verify_signature_get_times(sgid, out uint cr, out uint ex);
        DateTime exp = DateTimeOffset.FromUnixTimeSeconds(Util.PopLong(lib, (long)ex, ret)).LocalDateTime;
        DateTime cre = DateTimeOffset.FromUnixTimeSeconds(Util.PopLong(lib, (long)cr, ret)).LocalDateTime;
        return new DateTime[] { cre, exp };
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sgid;
}

}
