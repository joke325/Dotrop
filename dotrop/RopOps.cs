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
public class RopOpGenerate : RopObject {
    internal RopOpGenerate(RopBind own, RopHandle opid) {
        if(opid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.opid = opid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(opid != null) {
            ret = (int)lib.rnp_op_generate_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }

    // API

    public void set_bits(int bits) {
        int ret = (int)lib.rnp_op_generate_set_bits(opid, (uint)bits);
        Util.Return(ret);
    }
    public void set_hash(String hash) {
        int ret = (int)lib.rnp_op_generate_set_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_dsa_qbits(int qbits) {
        int ret = (int)lib.rnp_op_generate_set_dsa_qbits(opid, (uint)qbits);
        Util.Return(ret);
    }
    public void set_curve(string curve) {
        int ret = (int)lib.rnp_op_generate_set_curve(opid, curve);
        Util.Return(ret);
    }
    public void set_protection_password(string password) {
        int ret = (int)lib.rnp_op_generate_set_protection_password(opid, password);
        Util.Return(ret);
    }
    public void set_request_password(bool request) {
        int ret = (int)lib.rnp_op_generate_set_request_password(opid, request);
        Util.Return(ret);
    }
    public void set_protection_cipher(string cipher) {
        int ret = (int)lib.rnp_op_generate_set_protection_cipher(opid, cipher);
        Util.Return(ret);
    }
    public void set_protection_hash(string hash) {
        int ret = (int)lib.rnp_op_generate_set_protection_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_protection_mode(string mode) {
        int ret = (int)lib.rnp_op_generate_set_protection_mode(opid, mode);
        Util.Return(ret);
    }
    public void set_protection_iterations(int iterations) {
        int ret = (int)lib.rnp_op_generate_set_protection_iterations(opid, (uint)iterations);
        Util.Return(ret);
    }
    public void add_usage(string usage) {
        int ret = (int)lib.rnp_op_generate_add_usage(opid, usage);
        Util.Return(ret);
    }
    public void clear_usage() {
        int ret = (int)lib.rnp_op_generate_clear_usage(opid);
        Util.Return(ret);
    }
    public void set_usages(string[] usages) {
        clear_usage();
        foreach(string usage in usages)
            add_usage(usage);
    }
    public void set_userid(string userid) {
        int ret = (int)lib.rnp_op_generate_set_userid(opid, userid);
        Util.Return(ret);
    }
    public void set_expiration(TimeSpan expiration) {
        int ret = (int)lib.rnp_op_generate_set_expiration(opid, (uint)Util.TimeDelta2Sec(expiration));
        Util.Return(ret);
    }
    public void add_pref_hash(string hash) {
        int ret = (int)lib.rnp_op_generate_add_pref_hash(opid, hash);
        Util.Return(ret);
    }
    public void clear_pref_hashes() {
        int ret = (int)lib.rnp_op_generate_clear_pref_hashes(opid);
        Util.Return(ret);
    }
    public void set_pref_hashes(string[] hashes) {
        clear_pref_hashes();
        foreach(string hash in hashes)
            add_pref_hash(hash);
    }
    public void add_pref_compression(string compression) {
        int ret = (int)lib.rnp_op_generate_add_pref_compression(opid, compression);
        Util.Return(ret);
    }
    public void clear_pref_compression() {
        int ret = (int)lib.rnp_op_generate_clear_pref_compression(opid);
        Util.Return(ret);
    }
    public void set_pref_compressions(String[] compressions) {
        clear_pref_compression();
        foreach(string compression in compressions)
            add_pref_compression(compression);
    }
    public void add_pref_cipher(string cipher) {
        int ret = (int)lib.rnp_op_generate_add_pref_cipher(opid, cipher);
        Util.Return(ret);
    }
    public void clear_pref_ciphers() {
        int ret = (int)lib.rnp_op_generate_clear_pref_ciphers(opid);
        Util.Return(ret);
    }
    public void set_pref_ciphers(string[] ciphers) {
        clear_pref_ciphers();
        foreach(string cipher in ciphers)
            add_pref_cipher(cipher);
    }
    public void set_pref_keyserver(string keyserver) {
        int ret = (int)lib.rnp_op_generate_set_pref_keyserver(opid, keyserver);
        Util.Return(ret);
    }
    public void execute() {
        int ret = (int)lib.rnp_op_generate_execute(opid);
        Util.Return(ret);
    }
    public RopKey get_key(int tag = 0) {
        int ret = (int)lib.rnp_op_generate_get_key(opid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopKey uid = new RopKey(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(uid, tag);
            return uid;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
}
    
/** 
* version 0.3.1
* since   0.3.1
*/
public class RopOpSign : RopObject {
    internal RopOpSign(RopBind own, RopHandle opid) {
        if(opid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.opid = opid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(opid != null) {
            ret = (int)lib.rnp_op_sign_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }

    // API

    public void set_compression(string compression, int level) {
        int ret = (int)lib.rnp_op_sign_set_compression(opid, compression, level);
        Util.Return(ret);
    }
    public void set_armor(bool armored) {
        int ret = (int)lib.rnp_op_sign_set_armor(opid, armored);
        Util.Return(ret);
    }
    public void set_hash(string hash) {
        int ret = (int)lib.rnp_op_sign_set_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_creation_time(DateTime create) {
        int ret = (int)lib.rnp_op_sign_set_creation_time(opid, (uint)Util.Datetime2TS(create));
        Util.Return(ret);
    }
    public void set_expiration_time(DateTime expire) {
        int ret = (int)lib.rnp_op_sign_set_expiration_time(opid, (uint)Util.Datetime2TS(expire));
        Util.Return(ret);
    }
    public void set_expiration(TimeSpan expire) {
        int ret = (int)lib.rnp_op_sign_set_expiration_time(opid, (uint)Util.TimeDelta2Sec(expire));
        Util.Return(ret);
    }
    public void set_file_name(string filename) {
        int ret = (int)lib.rnp_op_sign_set_file_name(opid, filename);
        Util.Return(ret);
    }
    public void set_file_mtime(DateTime mtime) {
        int ret = (int)lib.rnp_op_sign_set_file_mtime(opid, (uint)Util.Datetime2TS(mtime));
        Util.Return(ret);
    }
    public void execute() {
        int ret = (int)lib.rnp_op_sign_execute(opid);
        Util.Return(ret);
    }
    public RopSignSignature add_signature(RopKey key) {
        int ret = (int)lib.rnp_op_sign_add_signature(opid, key!=null? key.getHandle() : RopHandle.Null, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind))
            return new RopSignSignature(bind, Util.PopHandle(lib, hnd, ret));
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopOpVerify : RopObject {
    internal RopOpVerify(RopBind own, RopHandle opid) {
        if(opid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.opid = opid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(opid != null) {
            ret = (int)lib.rnp_op_verify_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }
    
    // API

    public int signature_count() {
        int ret = (int)lib.rnp_op_verify_get_signature_count(opid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public void execute() {
        int ret = (int)lib.rnp_op_verify_execute(opid);
        Util.Return(ret);
    }
    public RopVeriSignature get_signature_at(int idx) {
        int ret = (int)lib.rnp_op_verify_get_signature_at(opid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind))
            return new RopVeriSignature(bind, Util.PopHandle(lib, hnd, ret));
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public FileInfo get_file_info() {
        int ret = (int)lib.rnp_op_verify_get_file_info(opid, out RopHandle fn, out uint mt);
        DateTime mtime = DateTimeOffset.FromUnixTimeSeconds(Util.PopLong(lib, (long)mt, ret)).LocalDateTime;
        return new FileInfo(Util.GetRopString(lib, ret, fn), mtime);
    }

    public struct ProtectionInfo {
        public string mode;
        public string cipher;
        public bool valid;
        public ProtectionInfo(string mode, string cipher, bool valid) { this.mode = mode; this.cipher = cipher; this.valid = valid; }
    }    
    public ProtectionInfo get_protection_info() {
        int ret = (int)lib.rnp_op_verify_get_protection_info(opid, out RopHandle md, out RopHandle cp, out bool vl);
        bool valid = Util.PopBool(lib, vl, ret);
        string cipher = Util.GetRopString(lib, ret, cp);
        return new ProtectionInfo(Util.GetRopString(lib, ret, md), cipher, valid);
    }
    public int get_recipient_count() {
        int ret = (int)lib.rnp_op_verify_get_recipient_count(opid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public RopRecipient get_used_recipient(int tag = 0) {
        int ret = (int)lib.rnp_op_verify_get_used_recipient(opid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopRecipient recp = new RopRecipient(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(recp, tag);
            return recp;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopRecipient get_recipient_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_op_verify_get_recipient_at(opid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopRecipient recp = new RopRecipient(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(recp, tag);
            return recp;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public int get_symenc_count() {
        int ret = (int)lib.rnp_op_verify_get_symenc_count(opid, out uint cn);
        return Util.PopInt(lib, (int)cn, ret);
    }
    public RopSymEnc get_used_symenc(int tag = 0) {
        int ret = (int)lib.rnp_op_verify_get_used_symenc(opid, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopSymEnc senc = new RopSymEnc(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(senc, tag);
            return senc;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopSymEnc get_symenc_at(int idx, int tag = 0) {
        int ret = (int)lib.rnp_op_verify_get_symenc_at(opid, (uint)idx, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopSymEnc senc = new RopSymEnc(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(senc, tag);
            return senc;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
    
    public struct FileInfo {
        public FileInfo(string fileName, DateTime mtime) { this.fileName = fileName; this.mtime = mtime; }
        public string fileName;
        public DateTime mtime;
    }
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopOpEncrypt : RopObject {
    internal RopOpEncrypt(RopBind own, RopHandle opid) {
        if(opid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.opid = opid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(opid != null) {
            ret = (int)lib.rnp_op_encrypt_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }
    
    // API

    public void add_recipient(RopKey key) {
        int ret = (int)lib.rnp_op_encrypt_add_recipient(opid, key!=null? key.getHandle() : null);
        Util.Return(ret);
    }
    public RopSignSignature add_signature(RopKey key) {
        int ret = (int)lib.rnp_op_encrypt_add_signature(opid, key!=null? key.getHandle() : null, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind))
            return new RopSignSignature(bind, Util.PopHandle(lib, hnd, ret));
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public void set_hash(string hash) {
        int ret = (int)lib.rnp_op_encrypt_set_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_creation_time(DateTime create) {
        int ret = (int)lib.rnp_op_encrypt_set_creation_time(opid, (uint)Util.Datetime2TS(create));
        Util.Return(ret);
    }
    public void set_expiration_time(DateTime expire) {
        int ret = (int)lib.rnp_op_encrypt_set_expiration_time(opid, (uint)Util.Datetime2TS(expire));
        Util.Return(ret);
    }
    public void add_password(string password, string s2kHash, int iterations, string s2kCipher) {
        int ret = (int)lib.rnp_op_encrypt_add_password(opid, password, s2kHash, (uint)iterations, s2kCipher);
        Util.Return(ret);
    }
    public void set_armor(bool armored) {
        int ret = (int)lib.rnp_op_encrypt_set_armor(opid, armored);
        Util.Return(ret);
    }
    public void set_cipher(string cipher) {
        int ret = (int)lib.rnp_op_encrypt_set_cipher(opid, cipher);
        Util.Return(ret);
    }
    public void set_aead(string alg) {
        int ret = (int)lib.rnp_op_encrypt_set_aead(opid, alg);
        Util.Return(ret);
    }
    public void set_aead_bits(int bits) {
        int ret = (int)lib.rnp_op_encrypt_set_aead_bits(opid, (uint)bits);
        Util.Return(ret);
    }
    public void set_compression(string compression, int level) {
        int ret = (int)lib.rnp_op_encrypt_set_compression(opid, compression, level);
        Util.Return(ret);
    }
    public void set_file_name(string filename) {
        int ret = (int)lib.rnp_op_encrypt_set_file_name(opid, filename);
        Util.Return(ret);
    }
    public void set_file_mtime(DateTime mtime) {
        int ret = (int)lib.rnp_op_encrypt_set_file_mtime(opid, (uint)Util.Datetime2TS(mtime));
        Util.Return(ret);
    }
    public void execute() {
        int ret = (int)lib.rnp_op_encrypt_execute(opid);
        Util.Return(ret);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopRecipient : RopObject {
    internal RopRecipient(RopBind own, RopHandle rid) {
        if(rid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.rid = rid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(rid != null) {
            rid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return rid;
    }

    // API

    public string get_keyid() {
        int ret = (int)lib.rnp_recipient_get_keyid(rid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string get_alg() {
        int ret = (int)lib.rnp_recipient_get_alg(rid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle rid;
}

/** 
* version 0.3.1
* since   0.3.1
*/
public class RopSymEnc : RopObject {
    internal RopSymEnc(RopBind own, RopHandle seid) {
        if(seid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.seid = seid;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(seid != null) {
            seid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return seid;
    }

    // API

    public string get_cipher() {
        int ret = (int)lib.rnp_symenc_get_cipher(seid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string get_aead_alg() {
        int ret = (int)lib.rnp_symenc_get_aead_alg(seid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string get_hash_alg() {
        int ret = (int)lib.rnp_symenc_get_hash_alg(seid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string get_s2k_type() {
        int ret = (int)lib.rnp_symenc_get_s2k_type(seid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public int get_s2k_iterations() {
        int ret = (int)lib.rnp_symenc_get_s2k_iterations(seid, out uint it);
        return Util.PopInt(lib, (int)it, ret);
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle seid;
}

}
