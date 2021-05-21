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
* <summary>Wraps FFI related ops</summary>
* version 0.14.0
* since   0.3.1
*/
public class RopSession : RopObject, RopPassCallBack, RopKeyCallBack {
    internal RopSession(RopBind own, RopHandle sid) {
        if(sid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sid = sid;
        this.passProvider = null;
        this.keyProvider = null;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(sid != null) {
            ret = (int)lib.rnp_ffi_destroy(sid);
            sid = null;
        }
        return ret;
    }

    public RopHandle getHandle() {
        return sid;
    }

    internal void Detach() {
        sid = null;
    }

    public WeakReference<RopBind> getBind() {
        return own;
    }

    // API

    public int public_key_count() {
        int ret = (int)lib.rnp_get_public_key_count(sid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public int secret_key_count() {
        int ret = (int)lib.rnp_get_secret_key_count(sid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }

    public RopOpSign op_sign_create(RopInput input, RopOutput output, bool cleartext = false, bool detached = false, int tag = 0) {
        int ret = ROPE.RNP_SUCCESS;
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        RopHandle op = null;
        if(cleartext)
            ret = (int)lib.rnp_op_sign_cleartext_create(out op, sid, inp, outp);
        else if(detached)
            ret = (int)lib.rnp_op_sign_detached_create(out op, sid, inp, outp);
        else
            ret = (int)lib.rnp_op_sign_create(out op, sid, inp, outp);
        if(own.TryGetTarget(out RopBind bind)) {
            RopOpSign sign = new RopOpSign(bind, Util.PopHandle(lib, op, ret));
            bind.PutObj(sign, tag);
            return sign;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopOpSign op_sign_create_cleartext(RopInput input, RopOutput output) {
        return op_sign_create(input, output, true, false);
    }
    public RopOpSign op_sign_create_detached(RopInput input, RopOutput output) {
        return op_sign_create(input, output, false, true);
    }
    public RopOpGenerate op_generate_create(string keyAlg, RopKey primary = null, int tag = 0) {
        int ret;
        RopHandle op = null;
        if(primary == null)
            ret = (int)lib.rnp_op_generate_create(out op, sid, keyAlg);
        else
            ret = (int)lib.rnp_op_generate_subkey_create(out op, sid, primary!=null? primary.getHandle() : RopHandle.Null, keyAlg);
        if(own.TryGetTarget(out RopBind bind)) {
            RopOpGenerate opg = new RopOpGenerate(bind, Util.PopHandle(lib, op, ret));
            bind.PutObj(opg, tag);
            return opg;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopOpEncrypt op_encrypt_create(RopInput input, RopOutput output, int tag = 0) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        int ret = (int)lib.rnp_op_encrypt_create(out RopHandle op, sid, inp, outp);
        if(own.TryGetTarget(out RopBind bind)) {
            RopOpEncrypt ope = new RopOpEncrypt(bind, Util.PopHandle(lib, op, ret));
            bind.PutObj(ope, tag);
            return ope;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopOpVerify op_verify_create(RopInput input, RopOutput output, RopInput signature = null, int tag = 0) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        int ret;
        RopHandle op = null;
        if(signature == null) {
            RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
            ret = (int)lib.rnp_op_verify_create(out op, sid, inp, outp);
        } else {
            RopHandle sig = (signature!=null? signature.getHandle() : RopHandle.Null);
            ret = (int)lib.rnp_op_verify_detached_create(out op, sid, inp, sig);
        }
        if(own.TryGetTarget(out RopBind bind)) {
            RopOpVerify opv = new RopOpVerify(bind, Util.PopHandle(lib, op, ret));
            bind.PutObj(opv, tag);
            return opv;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopOpVerify op_verify_create(RopInput input, RopInput signature) {
        return op_verify_create(input, null, signature);
    }
    public String request_password(RopKey key, object context) {
        RopHandle hkey = (key!=null? key.getHandle() : RopHandle.Null);
        int ret = (int)lib.rnp_request_password(sid, hkey, context, out RopHandle ps);
        RopHandle psw = Util.PopHandle(lib, ps, ret);
        String spsw = RopHandle.Str(psw);
        psw.ClearMemory();
        lib.rnp_buffer_destroy(psw);
        return spsw;
    }
    public void load_keys(string format, RopInput input, bool pub = true, bool sec = true) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        int ret = (int)lib.rnp_load_keys(sid, format, inp, (uint)flags);
        Util.Return(ret);
    }
    public void load_keys_public(String format, RopInput input) {
        load_keys(format, input, true, false);
    }
    public void load_keys_secret(String format, RopInput input) {
        load_keys(format, input, false, true);
    }    
    public void unload_keys(bool pub = true, bool sec = true) {
        int flags = (pub? ROPD.RNP_KEY_UNLOAD_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_UNLOAD_SECRET : 0);
        int ret = (int)lib.rnp_unload_keys(sid, (uint)flags);
        Util.Return(ret);
    }
    public void unload_keys_public() {
        unload_keys(true, false);
    }    
    public void unload_keys_secret() {
        unload_keys(false, true);
    }    
    private RopKey PutKey(RopHandle keyHnd, int tag = 0) {
        if(own.TryGetTarget(out RopBind bind)) {
            RopKey key = new RopKey(bind, keyHnd);
            bind.PutObj(key, tag);
            return key;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopKey locate_key(string identifier_type, string identifier, int tag = 0) {
        int ret = (int)lib.rnp_locate_key(sid, identifier_type, identifier, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_rsa(int bits, int subbits, String userid, String password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_rsa(sid, (uint)bits, (uint)subbits, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_dsa_eg(int bits, int subbits, String userid, String password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_dsa_eg(sid, (uint)bits, (uint)subbits, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_ec(String curve, String userid, String password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_ec(sid, curve, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_25519(String userid, String password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_25519(sid, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_sm2(String userid, String password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_sm2(sid, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopKey generate_key_ex(string keyAlg, string subAlg, int keyBits, int subBits, string keyCurve, string subCurve, string userid, string password, int tag = 0) {
        int ret = (int)lib.rnp_generate_key_ex(sid, keyAlg, subAlg, (uint)keyBits, (uint)subBits, keyCurve, subCurve, userid, password, out RopHandle hnd);
        return PutKey(Util.PopHandle(lib, hnd, ret), tag);
    }
    public RopData import_keys(RopInput input, bool pub = true, bool sec = true, bool perm = false, bool sngl = false) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        flags |= (perm? ROPD.RNP_LOAD_SAVE_PERMISSIVE : 0);
        flags |= (sngl? ROPD.RNP_LOAD_SAVE_SINGLE : 0);
        int ret = (int)lib.rnp_import_keys(sid, inp, (uint)flags, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            hnd = Util.PopHandle(lib, hnd, ret!=ROPE.RNP_ERROR_EOF? ret : ROPE.RNP_SUCCESS);
            if(ret != ROPE.RNP_ERROR_EOF) {
                RopData data = new RopData(bind, hnd, 0);
                bind.PutObj(data, 0);
                return data;
            }
            return null;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData import_keys_public(RopInput input, bool perm = false, bool sngl = false) {
        return import_keys(input, true, false, perm, sngl);
    }
    public RopData import_keys_secret(RopInput input, bool perm = false, bool sngl = false) {
        return import_keys(input, false, true, perm, sngl);
    }
    public RopData import_keys_single(RopInput input, bool pub = true, bool sec = true, bool perm = false) {
        return import_keys(input, pub, sec, perm, true);
    }

    public void set_pass_provider(SessionPassCallBack getpasscb, object getpasscbCtx) {
        passProvider = getpasscb;
        int ret = (int)lib.rnp_ffi_set_pass_provider(sid, this, getpasscbCtx);
        Util.Return(ret);
    }
    public RopIdIterator identifier_iterator_create(String identifier_type, int tag = 0) {
        int ret = (int)lib.rnp_identifier_iterator_create(sid, out RopHandle hnd, identifier_type);
        if(own.TryGetTarget(out RopBind bind)) {
            RopIdIterator iter = new RopIdIterator(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(iter, tag);
            return iter;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void set_log_fd(int fd) {
        int ret = (int)lib.rnp_ffi_set_log_fd(sid, fd);
        Util.Return(ret);
    }

    public void set_key_provider(SessionKeyCallBack getkeycb, object getkeycbCtx) {
        keyProvider = getkeycb;
        int ret = (int)lib.rnp_ffi_set_key_provider(sid, this, getkeycbCtx);
        Util.Return(ret);
    }
    
    public RopData import_signatures(RopInput input) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        int ret = (int)lib.rnp_import_signatures(sid, inp, 0, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    public void save_keys(string format, RopOutput output, bool pub = true, bool sec = true) {
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        int ret = (int)lib.rnp_save_keys(sid, format, outp, (uint)flags);
        Util.Return(ret);
    }
    public void save_keys_public(string format, RopOutput output) {
        save_keys(format, output, true, false);
    }
    public void save_keys_secret(string format, RopOutput output) {
        save_keys(format, output, false, true);
    }
    public RopData generate_key_json(RopData json) {
        int ret = (int)lib.rnp_generate_key_json(sid, json.getDataObj(), out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void decrypt(RopInput input, RopOutput output) {
        RopHandle inp = (input!=null? input.getHandle() : RopHandle.Null);
        RopHandle outp = (output!=null? output.getHandle() : RopHandle.Null);
        int ret = (int)lib.rnp_decrypt(sid, inp, outp);
        Util.Return(ret);
    }
    
    // Implements RopPassCallBack
    public RopPassCallBack.Ret PassCallBack(RopHandle ffi, object ctx, RopHandle key, RopHandle pgpCtx, RopHandle buf, int bufLen) {
        if(passProvider != null) {
            // create new Session and Key handlers
            RopSession ropSes = null;
            RopKey ropKey = null;
            try {
                if(own.TryGetTarget(out RopBind bind)) {
                    ropSes = (!ffi.IsNull()? new RopSession(bind, ffi) : null);
                    ropKey = (!key.IsNull()? new RopKey(bind, key) : null);
                    SessionPassCallBack.Ret scbRet = passProvider.PassCallBack(ropSes, ctx, ropKey, RopHandle.Str(pgpCtx), bufLen);
                    return new RopPassCallBack.Ret(scbRet.ret, scbRet.outBuf);
                }
                throw new RopError(RopBind.ROP_ERROR_INTERNAL);
            } catch(RopError) {
            } finally {
                if(ropSes != null)
                    ropSes.Detach();
                if(ropKey != null)
                    ropKey.Detach();
            }
        }
        return new RopPassCallBack.Ret(false, null);
    }

    // Implements RopKeyCallBack
    public void KeyCallBack(RopHandle ffi, object ctx, RopHandle identifierType, RopHandle identifier, bool secret) {
        if(keyProvider != null) {
            // create a new Session handler
            RopSession ropSes = null;
            try {
                if(own.TryGetTarget(out RopBind bind)) {
                    ropSes = (!ffi.IsNull()? new RopSession(bind, ffi) : null);
                    keyProvider.KeyCallBack(ropSes, ctx, RopHandle.Str(identifierType), RopHandle.Str(identifier), secret);
                }
                throw new RopError(RopBind.ROP_ERROR_INTERNAL);
            } catch(RopError) {
            } finally {
                if(ropSes != null)
                    ropSes.Detach();
            }
        }
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sid;
    private SessionPassCallBack passProvider;
    private SessionKeyCallBack keyProvider;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopIdIterator : RopObject {
    internal RopIdIterator(RopBind own, RopHandle iiid) {
        if(iiid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.lib = own.getLib();
        this.iiid = iiid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(iiid != null) {
            ret = (int)lib.rnp_identifier_iterator_destroy(iiid);
            iiid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return iiid;
    }

    public string next() {
        int ret = (int)lib.rnp_identifier_iterator_next(iiid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd, false);
    }
    
    private RopLib lib;
    private RopHandle iiid;
}

}
