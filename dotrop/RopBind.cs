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
using System.Collections.Generic;
using System.IO;
using tech.janky.dotrop.rop;


namespace tech.janky.dotrop {

/** 
* <summary>Root object of bindings for the RNP OpenPGP library</summary>
* version 0.14.0
* since   0.3.1
*/
public class RopBind {
    private int cnt;
    private RopLib lib;
    private List<int> tags;
    private SortedDictionary<int, SortedDictionary<RopObject, int> > t2objs;  //tag->set

    private void IniRopBind(bool checkLibVer) {
        this.cnt = 1;
        this.lib = new RopLib();
        this.tags = new List<int>(); 
        this.tags.Add(this.cnt);
        this.t2objs = new SortedDictionary<int, SortedDictionary<RopObject, int> >();
        if(checkLibVer && !(this.lib.rnp_version() >= this.lib.rnp_version_for(0, 9, 0)) && !((long)lib.rnp_version_commit_timestamp() >= ropid()))
            throw new RopError(ROP_ERROR_LIBVERSION);
    }
    
    /** 
    * Constructor
    */
    public RopBind() {
        IniRopBind(true);
    }

    /** 
    * Constructor
    */
    public RopBind(bool checkLibVer) {
        IniRopBind(checkLibVer);
    }	

    /** 
    * Terminates the instance
    */
    public void Close() {
        clear();
        if(lib != null)
            lib.CleanUp();
        lib = null;
    }	

    /** 
    * Access to the lower level interface, do not use unless inevitable!
    */
    public RopLib getLib() { return lib; }

    // API

    private string altHome = null;
    public string default_homedir() {
        int ret = (int)lib.rnp_get_default_homedir(out RopHandle hnd);
        if(ret == ROPE.RNP_ERROR_NOT_SUPPORTED) {
            if(altHome == null) {
                string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if(home != null)
                    altHome = Path.Combine(home, ".rnp");
            }
            if(altHome != null)
                return altHome;
        }
        return Util.GetRopString(lib, ret, hnd);
    }
    public string version_string() {
        return lib.rnp_version_string();
    }
    public string version_string_full() {
        return lib.rnp_version_string_full();
    }
    public int version() {
        return (int)lib.rnp_version();
    }
    public long version_commit_timestamp() {
        return (long)lib.rnp_version_commit_timestamp();
    }
    public string[] get_homedir_info(string homedir) {
        int ret = (int)lib.rnp_detect_homedir_info(homedir, out RopHandle h1, out RopHandle h2, out RopHandle h3, out RopHandle h4);
        return Util.GetRopStrings(lib, ret, new RopHandle[] {h1, h2, h3, h4});
    }
    public int version_for(int major, int minor, int patch) {
        return (int)lib.rnp_version_for((uint)major, (uint)minor, (uint)patch);
    }
    public int version_major(int version) {
        return (int)lib.rnp_version_major((uint)version);
    }
    public int version_minor(int version) {
        return (int)lib.rnp_version_minor((uint)version);
    }
    public int version_patch(int version) {
        return (int)lib.rnp_version_patch((uint)version);
    }
    public string result_to_string(int result) {
        return lib.rnp_result_to_string((uint)result);
    }
    public int enable_debug(string file) {
        return (int)lib.rnp_enable_debug(file);
    }
    public int disable_debug() {
        return (int)lib.rnp_disable_debug();
    }
    public bool supports_feature(string type, string name) {
        int ret = (int)lib.rnp_supports_feature(type, name, out bool sp);
        return Util.PopBool(lib, sp, ret);
    }
    public string supported_features(string type) {
        int ret = (int)lib.rnp_supported_features(type, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public string detect_key_format(RopData buf) {
        int ret = (int)lib.rnp_detect_key_format(buf.getDataObj(), buf.getDataLen(), out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public int calculate_iterations(string hash, int msec) {
        int ret = (int)lib.rnp_calculate_iterations(hash, msec, out int it);
        return Util.PopInt(lib, it, ret);
    }
    
    public RopSession create_session(string pubFormat, string secFormat, int tag = 0) {
        int ret = (int)lib.rnp_ffi_create(out RopHandle hnd, pubFormat, secFormat);
        RopSession ses = new RopSession(this, Util.PopHandle(lib, hnd, ret));
        PutObj(ses, tag);
        return ses;
    }

    public RopInput create_input(RopData buf, bool doCopy, int tag = 0) {
        int ret = (int)lib.rnp_input_from_memory(out RopHandle hnd, buf.getDataObj(), (uint)buf.getDataLen(), doCopy);
        RopInput inp = new RopInput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(inp, tag);
        return inp;
    }
    public RopInput create_input(String path, int tag = 0) {
        int ret = (int)lib.rnp_input_from_path(out RopHandle hnd, path);
        RopInput inp = new RopInput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(inp, tag);
        return inp;
    }
    public RopInput create_input(InputCallBack inputCB, object app_ctx, int tag = 0) {
        RopInput inp = new RopInput(this, inputCB);
        int ret = (int)lib.rnp_input_from_callback(out RopHandle hnd, inp, app_ctx);
        inp.Attach(Util.PopHandle(lib, hnd, ret));
        PutObj(inp, tag);
        return inp;
    }
    
    public RopOutput create_output(string toFile, bool overwrite, bool random, int tag = 0) {
        int flags = (overwrite? ROPD.RNP_OUTPUT_FILE_OVERWRITE : 0);
        flags |= (random? ROPD.RNP_OUTPUT_FILE_RANDOM : 0);
        int ret = (int)lib.rnp_output_to_file(out RopHandle hnd, toFile, (uint)flags);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(string toPath, int tag = 0) {
        int ret = (int)lib.rnp_output_to_path(out RopHandle hnd, toPath);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(outp, tag);
        return outp;
    }    
    public RopOutput create_output(object dummy = null, int tag = 0) {
        int ret = (int)lib.rnp_output_to_null(out RopHandle hnd);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(long maxAlloc, int tag = 0) {
        int ret = (int)lib.rnp_output_to_memory(out RopHandle hnd, maxAlloc);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, hnd, ret));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(OutputCallBack outputCB, Object app_ctx, int tag = 0) {
        RopOutput outp = new RopOutput(this, outputCB);
        int ret = (int)lib.rnp_output_to_callback(out RopHandle hnd, outp, app_ctx);
        outp.Attach(Util.PopHandle(lib, hnd, ret));
        PutObj(outp, tag);
        return outp;
    }

    /**
    * Tagging of allocated objects
    * @return tag of subsequestly allocated objects
    */
    public int tagging(int tag = 0) {
        cnt++;
        tags.Add(tag!=0? tag : cnt);
        return tags[tags.Count-1];
    }
    
    /**
    * Deletes tagged / specified objects
    */
    public void drop(int tag, object _object, object[] objects, object from) {
        int ret = ROPE.RNP_SUCCESS;
        
        // collect tags to delete
        List<int> dtags = new List<int>();
        LinkedList<int> tags2del = new LinkedList<int>();
        if(from != null) {
            int idx = tags.IndexOf((int)from);
            if(!(idx < 0))
                dtags = tags.GetRange(idx, tags.Count-idx);
        } else if(tag == 0 && tags.Count > 0)
            dtags.Add(tags[tags.Count-1]);
        else
            dtags.Add(tag);

        // collect objects to delete
        var objset = new SortedSet<RopObject>();
        if(objects != null)
            foreach(object obj in objects)
                if(typeof(RopObject).IsInstanceOfType(obj))
                    objset.Add((RopObject)obj);
        if(_object != null && typeof(RopObject).IsInstanceOfType(_object))
            objset.Add((RopObject)_object);

        // delete the dtags and objset conjuction
        SortedDictionary<int, RopObject> sorted = new SortedDictionary<int, RopObject>();
        foreach(int tg in (tag>=0? dtags : tags)) {
            SortedDictionary<RopObject, int> objs = null;
            if(t2objs.TryGetValue(tg, out objs) && objs != null) {
                var dellist = new SortedSet<RopObject>(objs.Keys);
                if(objset.Count > 0) {
                    dellist.IntersectWith(objset);
                }
                sorted.Clear();
                foreach(RopObject obj in dellist)
                    sorted.Add(objs[obj], obj);
                var rkeys = new List<int>(sorted.Keys);
                rkeys.Reverse();
                foreach(int nn in rkeys) {
                    RopObject obj = sorted[nn];
                    int err = obj.Close();
                    ret = (ret==ROPE.RNP_SUCCESS? err : ret);
                    objs.Remove(obj);
                }
                if(objs.Count == 0)
                    t2objs.Remove(tg);
            }
            
            // delete obsolete tags
            if(_object == null && objects == null && !t2objs.ContainsKey(tg))
                tags2del.AddFirst(tg);
        }
        foreach(int tg in tags2del)
            tags.Remove(tg);
        if(tags.Count == 0)
            tags.Add(1);
        if(tags.Count == 1)
            this.cnt = tags[tags.Count-1];

        if(ret != ROPE.RNP_SUCCESS)
            throw new RopError(ret);
    }
    public void drop(int tag = 0) {
        drop(tag, null, null, null);
    }
    public void drop_from(int from) {
        drop(0, null, null, from);
    }
    public void drop(object _object) {
        drop(0, _object, null, null);
    }
    public void drop(object[] objects) {
        drop(0, null, objects, null);
    }

    /**
    * To delete all objects
    */
    public void clear() {
        drop(-1);
    }

    // Tools

    internal void PutObj(RopObject obj, int tag) {
        int otag = (tag!=0? tag : tags[tags.Count-1]);
        if(!t2objs.TryGetValue(otag, out SortedDictionary<RopObject, int> objs) || objs == null)
            t2objs.Add(otag, objs = new SortedDictionary<RopObject, int>());
        this.cnt++;
        objs.Add(obj, this.cnt);
    }

    /**
    * Describes this object
    */
    public override string ToString() {
        return "tags = " + tags.Count + "\nt2objs = " + t2objs.Count;
    }

    public long ropid() {
        return 1610638124;
    }

    // Constants

    public const string KEYSTORE_GPG = ROPD.RNP_KEYSTORE_GPG;
    public const string KEYSTORE_KBX = ROPD.RNP_KEYSTORE_KBX;
    public const string KEYSTORE_G10 = ROPD.RNP_KEYSTORE_G10;
    public const string KEYSTORE_GPG21 = ROPD.RNP_KEYSTORE_GPG21;

    public const string ALG_HASH_MD5 = ROPD.RNP_ALGNAME_MD5;
    public const string ALG_HASH_SHA1 = ROPD.RNP_ALGNAME_SHA1;
    public const string ALG_HASH_SHA256 = ROPD.RNP_ALGNAME_SHA256;
    public const string ALG_HASH_SHA384 = ROPD.RNP_ALGNAME_SHA384;
    public const string ALG_HASH_SHA512 = ROPD.RNP_ALGNAME_SHA512;
    public const string ALG_HASH_SHA224 = ROPD.RNP_ALGNAME_SHA224;
    public const string ALG_HASH_SHA3_256 = ROPD.RNP_ALGNAME_SHA3_256;
    public const string ALG_HASH_SHA3_512 = ROPD.RNP_ALGNAME_SHA3_512;
    public const string ALG_HASH_RIPEMD160 = ROPD.RNP_ALGNAME_RIPEMD160;
    public const string ALG_HASH_SM3 = ROPD.RNP_ALGNAME_SM3;
    public const string ALG_HASH_DEFAULT = ALG_HASH_SHA256;
    public const string ALG_SYMM_IDEA = ROPD.RNP_ALGNAME_IDEA;
    public const string ALG_SYMM_TRIPLEDES = ROPD.RNP_ALGNAME_TRIPLEDES;
    public const string ALG_SYMM_CAST5 = ROPD.RNP_ALGNAME_CAST5;
    public const string ALG_SYMM_BLOWFISH = ROPD.RNP_ALGNAME_BLOWFISH;
    public const string ALG_SYMM_TWOFISH = ROPD.RNP_ALGNAME_TWOFISH;
    public const string ALG_SYMM_AES_128 = ROPD.RNP_ALGNAME_AES_128;
    public const string ALG_SYMM_AES_192 = ROPD.RNP_ALGNAME_AES_192;
    public const string ALG_SYMM_AES_256 = ROPD.RNP_ALGNAME_AES_256;
    public const string ALG_SYMM_CAMELLIA_128 = ROPD.RNP_ALGNAME_CAMELLIA_128;
    public const string ALG_SYMM_CAMELLIA_192 = ROPD.RNP_ALGNAME_CAMELLIA_192;
    public const string ALG_SYMM_CAMELLIA_256 = ROPD.RNP_ALGNAME_CAMELLIA_256;
    public const string ALG_SYMM_SM4 = ROPD.RNP_ALGNAME_SM4;
    public const string ALG_SYMM_DEFAULT = ALG_SYMM_AES_256;
    public const string ALG_ASYM_RSA = ROPD.RNP_ALGNAME_RSA;
    public const string ALG_ASYM_ELGAMAL = ROPD.RNP_ALGNAME_ELGAMAL;
    public const string ALG_ASYM_DSA = ROPD.RNP_ALGNAME_DSA;
    public const string ALG_ASYM_ECDH = ROPD.RNP_ALGNAME_ECDH;
    public const string ALG_ASYM_ECDSA = ROPD.RNP_ALGNAME_ECDSA;
    public const string ALG_ASYM_EDDSA = ROPD.RNP_ALGNAME_EDDSA;
    public const string ALG_ASYM_SM2 = ROPD.RNP_ALGNAME_SM2;
    public const string ALG_PLAINTEXT = ROPD.RNP_ALGNAME_PLAINTEXT;
    public const string ALG_CRC24 = ROPD.RNP_ALGNAME_CRC24;

    public const int ROP_ERROR_BAD_PARAMETERS = unchecked((int)0x80000000);
    public const int ROP_ERROR_LIBVERSION = unchecked((int)0x80000001);
    public const int ROP_ERROR_INTERNAL = unchecked((int)0x80000002);
    public const int ROP_ERROR_NULL_HANDLE = unchecked((int)0x80000003);


    public static void Main(string[] args) {
        // A trivial test
        try {
            throw new RopError(0);
        } catch (RopError) {
            Console.WriteLine("Starting:");
        }
        RopBind rop = null;
        try {
            rop = new RopBind();
            Console.WriteLine(rop.version_string_full());
            RopSession ses = rop.create_session("GPG", "GPG");
            Console.WriteLine("Session: " + ses.ToString());
            Console.WriteLine("Done.");
        } catch(RopError ex) {
            Console.WriteLine(ex);
        } finally {
            if(rop != null)
                rop.Close();
        }
    }
}

}
