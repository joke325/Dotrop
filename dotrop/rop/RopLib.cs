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
using System.Security;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace tech.janky.dotrop.rop {

/**
* version 0.14.0
* since   0.3.1
*/
public class RopLib {
    public RopLib() {
        retainsI = new SortedDictionary<RopHandle, RopHandle>();
        h2cb = new SortedDictionary<RopHandle, RopCB[]>();

        string[] roplibNames = new string[] { "librnp-0.dll", "librnp-0.so" };
        int idx = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)? 0 : 1), counter;
        for(counter = 0; counter < roplibNames.Length && lib == IntPtr.Zero; counter++, idx++) {
            try {
                IntPtr clib = NativeLibrary.Load(roplibNames[idx%roplibNames.Length]);
                lib = clib;
            } catch(DllNotFoundException) {}
        }
        if(lib == IntPtr.Zero)
            throw new DllNotFoundException("Missing library " + roplibNames[idx%roplibNames.Length]);
    }
    
    public int RetCounts() {
        return retainsI.Count;
    }

    public void CleanUp() {
        foreach(RopHandle hnd in h2cb.Keys)
            ClearCallbacks(hnd);
        foreach(var item in retainsI) {
            if(item.Value != null)
                item.Value.Source = IntPtr.Zero;
        }
        retainsI.Clear();
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr Result_to_string(uint p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr Version_string();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr Version_string_full();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Version();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Version_for(uint p0, uint p1, uint p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Version_major(uint p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Version_minor(uint p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Version_patch(uint p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate ulong Version_commit_timestamp();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Enable_debug(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Disable_debug();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Ffi_create(ref IntPtr p0, IntPtr p1, IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Ffi_destroy(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Ffi_set_log_fd(IntPtr p0, int p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Ffi_set_key_provider(IntPtr p0, Rop_get_key_cb p1, IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Ffi_set_pass_provider(IntPtr p0, Rop_password_cb p1, IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Get_default_homedir(ref IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Detect_homedir_info(IntPtr p0, ref IntPtr p1, ref IntPtr p2, ref IntPtr p3, ref IntPtr p4);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Detect_key_format(IntPtr p0, long p1, ref IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Calculate_iterations(IntPtr p0, long p1, ref IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Supports_feature(IntPtr p0, IntPtr p1, ref IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Supported_features(IntPtr p0, ref IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Request_password(IntPtr p0, IntPtr p1, IntPtr p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Load_keys(IntPtr p0, IntPtr p1, IntPtr p2, uint p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Unload_keys(IntPtr p0, uint p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Import_keys(IntPtr p0, IntPtr p1, uint p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Import_signatures(IntPtr p0, IntPtr p1, uint p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Save_keys(IntPtr p0, IntPtr p1, IntPtr p2, uint p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Get_public_key_count(IntPtr p0, ref IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Get_secret_key_count(IntPtr p0, ref IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Locate_key(IntPtr p0, IntPtr p1, IntPtr p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_handle_destroy(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_json(IntPtr p0, IntPtr p1, ref IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_rsa(IntPtr p0, uint p1, uint p2, IntPtr p3, IntPtr p4, ref IntPtr p5);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_dsa_eg(IntPtr p0, uint p1, uint p2, IntPtr p3, IntPtr p4, ref IntPtr p5);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_ec(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, ref IntPtr p4);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_25519(IntPtr p0, IntPtr p1, IntPtr p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_sm2(IntPtr p0, IntPtr p1, IntPtr p2, ref IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Generate_key_ex(IntPtr p0, IntPtr p1, IntPtr p2, uint p3, uint p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, ref IntPtr p9);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_create(ref IntPtr p0, IntPtr p1, IntPtr p2);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_subkey_create(ref IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_bits(IntPtr p0, uint p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_hash(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_dsa_qbits(IntPtr p0, uint p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_curve(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_protection_password(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_request_password(IntPtr p0, bool p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_protection_cipher(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_protection_hash(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_protection_mode(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_protection_iterations(IntPtr p0, uint p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_add_usage(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_clear_usage(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_userid(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_expiration(IntPtr p0, uint p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_add_pref_hash(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_clear_pref_hashes(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_add_pref_compression(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_clear_pref_compression(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_add_pref_cipher(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_clear_pref_ciphers(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_set_pref_keyserver(IntPtr p0, IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_execute(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_get_key(IntPtr p0, ref IntPtr p1);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_generate_destroy(IntPtr p0);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_export(IntPtr key, IntPtr output, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_export_autocrypt(IntPtr key, IntPtr subkey, IntPtr uid, IntPtr output, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_export_revocation(IntPtr key, IntPtr output, uint flags, IntPtr hash, IntPtr code, IntPtr reason);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_revoke(IntPtr key, uint flags, IntPtr hash, IntPtr code, IntPtr reason);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_remove(IntPtr key, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Guess_contents(IntPtr input, ref IntPtr contents);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Enarmor(IntPtr input, IntPtr output, IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Dearmor(IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_primary_uid(IntPtr key, ref IntPtr uid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_uid_count(IntPtr key, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_uid_at(IntPtr key, uint idx, ref IntPtr uid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_uid_handle_at(IntPtr key, uint idx, ref IntPtr uid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_get_type(IntPtr uid, ref IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_get_data(IntPtr uid, ref IntPtr data, ref IntPtr size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_is_primary(IntPtr uid, ref IntPtr primary);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_is_valid(IntPtr uid, ref IntPtr valid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_signature_count(IntPtr key, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_signature_at(IntPtr key, uint idx, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_revocation_signature(IntPtr key, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_get_signature_count(IntPtr uid, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_get_signature_at(IntPtr uid, uint idx, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_type(IntPtr sig, ref IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_alg(IntPtr sig, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_hash_alg(IntPtr sig, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_creation(IntPtr sig, ref IntPtr create);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_keyid(IntPtr sig, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_get_signer(IntPtr sig, ref IntPtr key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_is_valid(IntPtr sig, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_packet_to_json(IntPtr sig, uint flags, ref IntPtr json);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Signature_handle_destroy(IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_is_revoked(IntPtr uid, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_get_revocation_signature(IntPtr uid, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Uid_handle_destroy(IntPtr uid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_subkey_count(IntPtr key, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_subkey_at(IntPtr key, uint idx, ref IntPtr subkey);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_alg(IntPtr key, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_bits(IntPtr key, ref IntPtr bits);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_dsa_qbits(IntPtr key, ref IntPtr qbits);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_curve(IntPtr key, ref IntPtr curve);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_add_uid(IntPtr key, IntPtr uid, IntPtr hash, uint expiration, uint key_flags, bool primary);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_fprint(IntPtr key, ref IntPtr fprint);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_keyid(IntPtr key, ref IntPtr keyid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_grip(IntPtr key, ref IntPtr grip);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_primary_grip(IntPtr key, ref IntPtr grip);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_primary_fprint(IntPtr key, ref IntPtr fprint);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_allows_usage(IntPtr key, IntPtr usage, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_creation(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_expiration(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_set_expiration(IntPtr key, uint expiry);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_valid(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_valid_till(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_revoked(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_revocation_reason(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_superseded(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_compromised(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_retired(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_locked(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_protection_type(IntPtr key, ref IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_protection_mode(IntPtr key, ref IntPtr mode);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_protection_cipher(IntPtr key, ref IntPtr cipher);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_protection_hash(IntPtr key, ref IntPtr hash);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_get_protection_iterations(IntPtr key, ref IntPtr iterations);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_lock(IntPtr key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_unlock(IntPtr key, IntPtr password);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_protected(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_protect(IntPtr handle, IntPtr password, IntPtr cipher, IntPtr cipher_mode, IntPtr hash, uint iterations);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_unprotect(IntPtr key, IntPtr password);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_primary(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_is_sub(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_have_secret(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_have_public(IntPtr key, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_packets_to_json(IntPtr key, bool secret, uint flags, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Dump_packets_to_json(IntPtr input, uint flags, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Dump_packets_to_output(IntPtr  input, IntPtr output, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_cleartext_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_detached_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr signature);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_add_signature(IntPtr op, IntPtr key, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_signature_set_hash(IntPtr sig, IntPtr hash);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_signature_set_creation_time(IntPtr sig, uint create);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_signature_set_expiration_time(IntPtr sig, uint expires);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_compression(IntPtr op, IntPtr compression, int level);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_armor(IntPtr op, bool armored);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_hash(IntPtr op, IntPtr hash);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_creation_time(IntPtr op, uint create);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_expiration_time(IntPtr op, uint expire);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_file_name(IntPtr op, IntPtr filename);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_set_file_mtime(IntPtr op, uint mtime);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_execute(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_sign_destroy(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_detached_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr signature);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_execute(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_signature_count(IntPtr op, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_signature_at(IntPtr op, uint idx, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_file_info(IntPtr op, ref IntPtr filename, ref IntPtr mtime);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_protection_info(IntPtr op, ref IntPtr mode, ref IntPtr cipher, ref IntPtr valid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_recipient_count(IntPtr op, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_used_recipient(IntPtr op, ref IntPtr recipient);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_recipient_at(IntPtr op, uint idx, ref IntPtr recipient);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Recipient_get_keyid(IntPtr recipient, ref IntPtr keyid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Recipient_get_alg(IntPtr recipient, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_symenc_count(IntPtr op, ref IntPtr count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_used_symenc(IntPtr op, ref IntPtr symenc);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_get_symenc_at(IntPtr op, uint idx, ref IntPtr symenc);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Symenc_get_cipher(IntPtr symenc, ref IntPtr cipher);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Symenc_get_aead_alg(IntPtr symenc, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Symenc_get_hash_alg(IntPtr symenc, ref IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Symenc_get_s2k_type(IntPtr symenc, ref IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Symenc_get_s2k_iterations(IntPtr symenc, ref IntPtr iterations);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_destroy(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_signature_get_status(IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_signature_get_handle(IntPtr sig, ref IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_signature_get_hash(IntPtr sig, ref IntPtr hash);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_signature_get_key(IntPtr sig, ref IntPtr key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_verify_signature_get_times(IntPtr sig, ref IntPtr create, ref IntPtr expires);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void Buffer_destroy(IntPtr ptr);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Input_from_path(ref IntPtr input, IntPtr path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Input_from_memory(ref IntPtr input, IntPtr buf, long buf_len, bool do_copy);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Input_from_callback(ref IntPtr input, Rop_input_reader reader, Rop_input_closer closer, IntPtr app_ctx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Input_destroy(IntPtr input);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_path(ref IntPtr output, IntPtr path);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_file(ref IntPtr output, IntPtr path, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_memory(ref IntPtr output, long max_alloc);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_armor(IntPtr _base, ref IntPtr output, IntPtr type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_memory_get_buf(IntPtr output, ref IntPtr buf, ref IntPtr len, bool do_copy);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_callback(ref IntPtr output, Rop_output_writer writer, Rop_output_closer closer, IntPtr app_ctx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_to_null(ref IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_write(IntPtr output, IntPtr data, long size, ref IntPtr written);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_finish(IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_destroy(IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_create(ref IntPtr op, IntPtr ffi, IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_add_recipient(IntPtr op, IntPtr key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_add_signature(IntPtr op, IntPtr key, ref IntPtr sig);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_hash(IntPtr op, IntPtr hash);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_creation_time(IntPtr op, uint create);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_expiration_time(IntPtr op, uint expire);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_add_password(IntPtr op, IntPtr password, IntPtr s2k_hash, long iterations, IntPtr s2k_cipher);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_armor(IntPtr op, bool armored);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_cipher(IntPtr op, IntPtr cipher);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_aead(IntPtr op, IntPtr alg);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_aead_bits(IntPtr op, uint bits);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_compression(IntPtr op, IntPtr compression, int level);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_file_name(IntPtr op, IntPtr filename);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_set_file_mtime(IntPtr op, uint mtime);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_execute(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Op_encrypt_destroy(IntPtr op);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Decrypt(IntPtr ffi, IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Get_public_key_data(IntPtr handle, ref IntPtr buf, ref IntPtr buf_len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Get_secret_key_data(IntPtr handle, ref IntPtr buf, ref IntPtr buf_len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Key_to_json(IntPtr handle, uint flags, ref IntPtr result);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Identifier_iterator_create(IntPtr ffi, ref IntPtr it, IntPtr identifier_type);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Identifier_iterator_next(IntPtr it, ref IntPtr identifier);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Identifier_iterator_destroy(IntPtr it);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_pipe(IntPtr input, IntPtr output);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Output_armor_set_line_length(IntPtr output, uint llen);

    private enum LibSymID {
        result_to_string = 0,
        version_string,
        version_string_full,
        version,
        version_for,
        version_major,
        version_minor,
        version_patch,
        version_commit_timestamp,
        enable_debug,
        disable_debug,
        ffi_create,
        ffi_destroy,
        ffi_set_log_fd,
        ffi_set_key_provider,
        ffi_set_pass_provider,
        get_default_homedir,
        detect_homedir_info,
        detect_key_format,
        calculate_iterations,
        supports_feature,
        supported_features,
        request_password,
        load_keys,
        unload_keys,
        import_keys,
        import_signatures,
        save_keys,
        get_public_key_count,
        get_secret_key_count,
        locate_key,
        key_handle_destroy,
        generate_key_json,
        generate_key_rsa,
        generate_key_dsa_eg,
        generate_key_ec,
        generate_key_25519,
        generate_key_sm2,
        generate_key_ex,
        op_generate_create,
        op_generate_subkey_create,
        op_generate_set_bits,
        op_generate_set_hash,
        op_generate_set_dsa_qbits,
        op_generate_set_curve,
        op_generate_set_protection_password,
        op_generate_set_request_password,
        op_generate_set_protection_cipher,
        op_generate_set_protection_hash,
        op_generate_set_protection_mode,
        op_generate_set_protection_iterations,
        op_generate_add_usage,
        op_generate_clear_usage,
        op_generate_set_userid,
        op_generate_set_expiration,
        op_generate_add_pref_hash,
        op_generate_clear_pref_hashes,
        op_generate_add_pref_compression,
        op_generate_clear_pref_compression,
        op_generate_add_pref_cipher,
        op_generate_clear_pref_ciphers,
        op_generate_set_pref_keyserver,
        op_generate_execute,
        op_generate_get_key,
        op_generate_destroy,
        key_export,
        key_export_autocrypt,
        key_export_revocation,
        key_revoke,
        key_remove,
        guess_contents,
        enarmor,
        dearmor,
        key_get_primary_uid,
        key_get_uid_count,
        key_get_uid_at,
        key_get_uid_handle_at,
        uid_get_type,
        uid_get_data,
        uid_is_primary,
        uid_is_valid,
        key_get_signature_count,
        key_get_signature_at,
        key_get_revocation_signature,
        uid_get_signature_count,
        uid_get_signature_at,
        signature_get_type,
        signature_get_alg,
        signature_get_hash_alg,
        signature_get_creation,
        signature_get_keyid,
        signature_get_signer,
        signature_is_valid,
        signature_packet_to_json,
        signature_handle_destroy,
        uid_is_revoked,
        uid_get_revocation_signature,
        uid_handle_destroy,
        key_get_subkey_count,
        key_get_subkey_at,
        key_get_alg,
        key_get_bits,
        key_get_dsa_qbits,
        key_get_curve,
        key_add_uid,
        key_get_fprint,
        key_get_keyid,
        key_get_grip,
        key_get_primary_grip,
        key_get_primary_fprint,
        key_allows_usage,
        key_get_creation,
        key_get_expiration,
        key_set_expiration,
        key_is_valid,
        key_valid_till,
        key_is_revoked,
        key_get_revocation_reason,
        key_is_superseded,
        key_is_compromised,
        key_is_retired,
        key_is_locked,
        key_get_protection_type,
        key_get_protection_mode,
        key_get_protection_cipher,
        key_get_protection_hash,
        key_get_protection_iterations,
        key_lock,
        key_unlock,
        key_is_protected,
        key_protect,
        key_unprotect,
        key_is_primary,
        key_is_sub,
        key_have_secret,
        key_have_public,
        key_packets_to_json,
        dump_packets_to_json,
        dump_packets_to_output,
        op_sign_create,
        op_sign_cleartext_create,
        op_sign_detached_create,
        op_sign_add_signature,
        op_sign_signature_set_hash,
        op_sign_signature_set_creation_time,
        op_sign_signature_set_expiration_time,
        op_sign_set_compression,
        op_sign_set_armor,
        op_sign_set_hash,
        op_sign_set_creation_time,
        op_sign_set_expiration_time,
        op_sign_set_file_name,
        op_sign_set_file_mtime,
        op_sign_execute,
        op_sign_destroy,
        op_verify_create,
        op_verify_detached_create,
        op_verify_execute,
        op_verify_get_signature_count,
        op_verify_get_signature_at,
        op_verify_get_file_info,
        op_verify_get_protection_info,
        op_verify_get_recipient_count,
        op_verify_get_used_recipient,
        op_verify_get_recipient_at,
        recipient_get_keyid,
        recipient_get_alg,
        op_verify_get_symenc_count,
        op_verify_get_used_symenc,
        op_verify_get_symenc_at,
        symenc_get_cipher,
        symenc_get_aead_alg,
        symenc_get_hash_alg,
        symenc_get_s2k_type,
        symenc_get_s2k_iterations,
        op_verify_destroy,
        op_verify_signature_get_status,
        op_verify_signature_get_handle,
        op_verify_signature_get_hash,
        op_verify_signature_get_key,
        op_verify_signature_get_times,
        buffer_destroy,
        input_from_path,
        input_from_memory,
        input_from_callback,
        input_destroy,
        output_to_path,
        output_to_file,
        output_to_memory,
        output_to_armor,
        output_memory_get_buf,
        output_to_callback,
        output_to_null,
        output_write,
        output_finish,
        output_destroy,
        op_encrypt_create,
        op_encrypt_add_recipient,
        op_encrypt_add_signature,
        op_encrypt_set_hash,
        op_encrypt_set_creation_time,
        op_encrypt_set_expiration_time,
        op_encrypt_add_password,
        op_encrypt_set_armor,
        op_encrypt_set_cipher,
        op_encrypt_set_aead,
        op_encrypt_set_aead_bits,
        op_encrypt_set_compression,
        op_encrypt_set_file_name,
        op_encrypt_set_file_mtime,
        op_encrypt_execute,
        op_encrypt_destroy,
        decrypt,
        get_public_key_data,
        get_secret_key_data,
        key_to_json,
        identifier_iterator_create,
        identifier_iterator_next,
        identifier_iterator_destroy,
        output_pipe,
        output_armor_set_line_length,
        
        lib_sym_count
    }

    private Delegate FFIFunction(LibSymID symbol) {
        Delegate fx = null;
        if(!libSymbols.TryGetValue(symbol, out fx)) {
            IntPtr symb;
            string fname = null;
            Type ftype = null;
            switch(symbol) {
            default: ;
            break; case LibSymID.result_to_string:
                fname = "rnp_result_to_string"; ftype = typeof(Result_to_string);
            break; case LibSymID.version_string:
                fname = "rnp_version_string"; ftype = typeof(Version_string);
            break; case LibSymID.version_string_full:
                fname = "rnp_version_string_full"; ftype = typeof(Version_string_full);
            break; case LibSymID.version:
                fname = "rnp_version"; ftype = typeof(Version);
            break; case LibSymID.version_for:
                fname = "rnp_version_for"; ftype = typeof(Version_for);
            break; case LibSymID.version_major:
                fname = "rnp_version_major"; ftype = typeof(Version_major);
            break; case LibSymID.version_minor:
                fname = "rnp_version_minor"; ftype = typeof(Version_minor);
            break; case LibSymID.version_patch:
                fname = "rnp_version_patch"; ftype = typeof(Version_patch);
            break; case LibSymID.version_commit_timestamp:
                fname = "rnp_version_commit_timestamp"; ftype = typeof(Version_commit_timestamp);
            break; case LibSymID.enable_debug:
                fname = "rnp_enable_debug"; ftype = typeof(Enable_debug);
            break; case LibSymID.disable_debug:
                fname = "rnp_disable_debug"; ftype = typeof(Disable_debug);
            break; case LibSymID.ffi_create:
                fname = "rnp_ffi_create"; ftype = typeof(Ffi_create);
            break; case LibSymID.ffi_destroy:
                fname = "rnp_ffi_destroy"; ftype = typeof(Ffi_destroy);
            break; case LibSymID.ffi_set_log_fd:
                fname = "rnp_ffi_set_log_fd"; ftype = typeof(Ffi_set_log_fd);
            break; case LibSymID.ffi_set_key_provider:
                fname = "rnp_ffi_set_key_provider"; ftype = typeof(Ffi_set_key_provider);
            break; case LibSymID.ffi_set_pass_provider:
                fname = "rnp_ffi_set_pass_provider"; ftype = typeof(Ffi_set_pass_provider);
            break; case LibSymID.get_default_homedir:
                fname = "rnp_get_default_homedir"; ftype = typeof(Get_default_homedir);
            break; case LibSymID.detect_homedir_info:
                fname = "rnp_detect_homedir_info"; ftype = typeof(Detect_homedir_info);
            break; case LibSymID.detect_key_format:
                fname = "rnp_detect_key_format"; ftype = typeof(Detect_key_format);
            break; case LibSymID.calculate_iterations:
                fname = "rnp_calculate_iterations"; ftype = typeof(Calculate_iterations);
            break; case LibSymID.supports_feature:
                fname = "rnp_supports_feature"; ftype = typeof(Supports_feature);
            break; case LibSymID.supported_features:
                fname = "rnp_supported_features"; ftype = typeof(Supported_features);
            break; case LibSymID.request_password:
                fname = "rnp_request_password"; ftype = typeof(Request_password);
            break; case LibSymID.load_keys:
                fname = "rnp_load_keys"; ftype = typeof(Load_keys);
            break; case LibSymID.unload_keys:
                fname = "rnp_unload_keys"; ftype = typeof(Unload_keys);
            break; case LibSymID.import_keys:
                fname = "rnp_import_keys"; ftype = typeof(Import_keys);
            break; case LibSymID.import_signatures:
                fname = "rnp_import_signatures"; ftype = typeof(Import_signatures);
            break; case LibSymID.save_keys:
                fname = "rnp_save_keys"; ftype = typeof(Save_keys);
            break; case LibSymID.get_public_key_count:
                fname = "rnp_get_public_key_count"; ftype = typeof(Get_public_key_count);
            break; case LibSymID.get_secret_key_count:
                fname = "rnp_get_secret_key_count"; ftype = typeof(Get_secret_key_count);
            break; case LibSymID.locate_key:
                fname = "rnp_locate_key"; ftype = typeof(Locate_key);
            break; case LibSymID.key_handle_destroy:
                fname = "rnp_key_handle_destroy"; ftype = typeof(Key_handle_destroy);
            break; case LibSymID.generate_key_json:
                fname = "rnp_generate_key_json"; ftype = typeof(Generate_key_json);
            break; case LibSymID.generate_key_rsa:
                fname = "rnp_generate_key_rsa"; ftype = typeof(Generate_key_rsa);
            break; case LibSymID.generate_key_dsa_eg:
                fname = "rnp_generate_key_dsa_eg"; ftype = typeof(Generate_key_dsa_eg);
            break; case LibSymID.generate_key_ec:
                fname = "rnp_generate_key_ec"; ftype = typeof(Generate_key_ec);
            break; case LibSymID.generate_key_25519:
                fname = "rnp_generate_key_25519"; ftype = typeof(Generate_key_25519);
            break; case LibSymID.generate_key_sm2:
                fname = "rnp_generate_key_sm2"; ftype = typeof(Generate_key_sm2);
            break; case LibSymID.generate_key_ex:
                fname = "rnp_generate_key_ex"; ftype = typeof(Generate_key_ex);
            break; case LibSymID.op_generate_create:
                fname = "rnp_op_generate_create"; ftype = typeof(Op_generate_create);
            break; case LibSymID.op_generate_subkey_create:
                fname = "rnp_op_generate_subkey_create"; ftype = typeof(Op_generate_subkey_create);
            break; case LibSymID.op_generate_set_bits:
                fname = "rnp_op_generate_set_bits"; ftype = typeof(Op_generate_set_bits);
            break; case LibSymID.op_generate_set_hash:
                fname = "rnp_op_generate_set_hash"; ftype = typeof(Op_generate_set_hash);
            break; case LibSymID.op_generate_set_dsa_qbits:
                fname = "rnp_op_generate_set_dsa_qbits"; ftype = typeof(Op_generate_set_dsa_qbits);
            break; case LibSymID.op_generate_set_curve:
                fname = "rnp_op_generate_set_curve"; ftype = typeof(Op_generate_set_curve);
            break; case LibSymID.op_generate_set_protection_password:
                fname = "rnp_op_generate_set_protection_password"; ftype = typeof(Op_generate_set_protection_password);
            break; case LibSymID.op_generate_set_request_password:
                fname = "rnp_op_generate_set_request_password"; ftype = typeof(Op_generate_set_request_password);
            break; case LibSymID.op_generate_set_protection_cipher:
                fname = "rnp_op_generate_set_protection_cipher"; ftype = typeof(Op_generate_set_protection_cipher);
            break; case LibSymID.op_generate_set_protection_hash:
                fname = "rnp_op_generate_set_protection_hash"; ftype = typeof(Op_generate_set_protection_hash);
            break; case LibSymID.op_generate_set_protection_mode:
                fname = "rnp_op_generate_set_protection_mode"; ftype = typeof(Op_generate_set_protection_mode);
            break; case LibSymID.op_generate_set_protection_iterations:
                fname = "rnp_op_generate_set_protection_iterations"; ftype = typeof(Op_generate_set_protection_iterations);
            break; case LibSymID.op_generate_add_usage:
                fname = "rnp_op_generate_add_usage"; ftype = typeof(Op_generate_add_usage);
            break; case LibSymID.op_generate_clear_usage:
                fname = "rnp_op_generate_clear_usage"; ftype = typeof(Op_generate_clear_usage);
            break; case LibSymID.op_generate_set_userid:
                fname = "rnp_op_generate_set_userid"; ftype = typeof(Op_generate_set_userid);
            break; case LibSymID.op_generate_set_expiration:
                fname = "rnp_op_generate_set_expiration"; ftype = typeof(Op_generate_set_expiration);
            break; case LibSymID.op_generate_add_pref_hash:
                fname = "rnp_op_generate_add_pref_hash"; ftype = typeof(Op_generate_add_pref_hash);
            break; case LibSymID.op_generate_clear_pref_hashes:
                fname = "rnp_op_generate_clear_pref_hashes"; ftype = typeof(Op_generate_clear_pref_hashes);
            break; case LibSymID.op_generate_add_pref_compression:
                fname = "rnp_op_generate_add_pref_compression"; ftype = typeof(Op_generate_add_pref_compression);
            break; case LibSymID.op_generate_clear_pref_compression:
                fname = "rnp_op_generate_clear_pref_compression"; ftype = typeof(Op_generate_clear_pref_compression);
            break; case LibSymID.op_generate_add_pref_cipher:
                fname = "rnp_op_generate_add_pref_cipher"; ftype = typeof(Op_generate_add_pref_cipher);
            break; case LibSymID.op_generate_clear_pref_ciphers:
                fname = "rnp_op_generate_clear_pref_ciphers"; ftype = typeof(Op_generate_clear_pref_ciphers);
            break; case LibSymID.op_generate_set_pref_keyserver:
                fname = "rnp_op_generate_set_pref_keyserver"; ftype = typeof(Op_generate_set_pref_keyserver);
            break; case LibSymID.op_generate_execute:
                fname = "rnp_op_generate_execute"; ftype = typeof(Op_generate_execute);
            break; case LibSymID.op_generate_get_key:
                fname = "rnp_op_generate_get_key"; ftype = typeof(Op_generate_get_key);
            break; case LibSymID.op_generate_destroy:
                fname = "rnp_op_generate_destroy"; ftype = typeof(Op_generate_destroy);
            break; case LibSymID.key_export:
                fname = "rnp_key_export"; ftype = typeof(Key_export);
            break; case LibSymID.key_export_autocrypt:
                fname = "rnp_key_export_autocrypt"; ftype = typeof(Key_export_autocrypt);
            break; case LibSymID.key_export_revocation:
                fname = "rnp_key_export_revocation"; ftype = typeof(Key_export_revocation);
            break; case LibSymID.key_revoke:
                fname = "rnp_key_revoke"; ftype = typeof(Key_revoke);
            break; case LibSymID.key_remove:
                fname = "rnp_key_remove"; ftype = typeof(Key_remove);
            break; case LibSymID.guess_contents:
                fname = "rnp_guess_contents"; ftype = typeof(Guess_contents);
            break; case LibSymID.enarmor:
                fname = "rnp_enarmor"; ftype = typeof(Enarmor);
            break; case LibSymID.dearmor:
                fname = "rnp_dearmor"; ftype = typeof(Dearmor);
            break; case LibSymID.key_get_primary_uid:
                fname = "rnp_key_get_primary_uid"; ftype = typeof(Key_get_primary_uid);
            break; case LibSymID.key_get_uid_count:
                fname = "rnp_key_get_uid_count"; ftype = typeof(Key_get_uid_count);
            break; case LibSymID.key_get_uid_at:
                fname = "rnp_key_get_uid_at"; ftype = typeof(Key_get_uid_at);
            break; case LibSymID.key_get_uid_handle_at:
                fname = "rnp_key_get_uid_handle_at"; ftype = typeof(Key_get_uid_handle_at);
            break; case LibSymID.uid_get_type:
                fname = "rnp_uid_get_type"; ftype = typeof(Uid_get_type);
            break; case LibSymID.uid_get_data:
                fname = "rnp_uid_get_data"; ftype = typeof(Uid_get_data);
            break; case LibSymID.uid_is_primary:
                fname = "rnp_uid_is_primary"; ftype = typeof(Uid_is_primary);
            break; case LibSymID.uid_is_valid:
                fname = "rnp_uid_is_valid"; ftype = typeof(Uid_is_valid);
            break; case LibSymID.key_get_signature_count:
                fname = "rnp_key_get_signature_count"; ftype = typeof(Key_get_signature_count);
            break; case LibSymID.key_get_signature_at:
                fname = "rnp_key_get_signature_at"; ftype = typeof(Key_get_signature_at);
            break; case LibSymID.key_get_revocation_signature:
                fname = "rnp_key_get_revocation_signature"; ftype = typeof(Key_get_revocation_signature);
            break; case LibSymID.uid_get_signature_count:
                fname = "rnp_uid_get_signature_count"; ftype = typeof(Uid_get_signature_count);
            break; case LibSymID.uid_get_signature_at:
                fname = "rnp_uid_get_signature_at"; ftype = typeof(Uid_get_signature_at);
            break; case LibSymID.signature_get_type:
                fname = "rnp_signature_get_type"; ftype = typeof(Signature_get_type);
            break; case LibSymID.signature_get_alg:
                fname = "rnp_signature_get_alg"; ftype = typeof(Signature_get_alg);
            break; case LibSymID.signature_get_hash_alg:
                fname = "rnp_signature_get_hash_alg"; ftype = typeof(Signature_get_hash_alg);
            break; case LibSymID.signature_get_creation:
                fname = "rnp_signature_get_creation"; ftype = typeof(Signature_get_creation);
            break; case LibSymID.signature_get_keyid:
                fname = "rnp_signature_get_keyid"; ftype = typeof(Signature_get_keyid);
            break; case LibSymID.signature_get_signer:
                fname = "rnp_signature_get_signer"; ftype = typeof(Signature_get_signer);
            break; case LibSymID.signature_is_valid:
                fname = "rnp_signature_is_valid"; ftype = typeof(Signature_is_valid);
            break; case LibSymID.signature_packet_to_json:
                fname = "rnp_signature_packet_to_json"; ftype = typeof(Signature_packet_to_json);
            break; case LibSymID.signature_handle_destroy:
                fname = "rnp_signature_handle_destroy"; ftype = typeof(Signature_handle_destroy);
            break; case LibSymID.uid_is_revoked:
                fname = "rnp_uid_is_revoked"; ftype = typeof(Uid_is_revoked);
            break; case LibSymID.uid_get_revocation_signature:
                fname = "rnp_uid_get_revocation_signature"; ftype = typeof(Uid_get_revocation_signature);
            break; case LibSymID.uid_handle_destroy:
                fname = "rnp_uid_handle_destroy"; ftype = typeof(Uid_handle_destroy);
            break; case LibSymID.key_get_subkey_count:
                fname = "rnp_key_get_subkey_count"; ftype = typeof(Key_get_subkey_count);
            break; case LibSymID.key_get_subkey_at:
                fname = "rnp_key_get_subkey_at"; ftype = typeof(Key_get_subkey_at);
            break; case LibSymID.key_get_alg:
                fname = "rnp_key_get_alg"; ftype = typeof(Key_get_alg);
            break; case LibSymID.key_get_bits:
                fname = "rnp_key_get_bits"; ftype = typeof(Key_get_bits);
            break; case LibSymID.key_get_dsa_qbits:
                fname = "rnp_key_get_dsa_qbits"; ftype = typeof(Key_get_dsa_qbits);
            break; case LibSymID.key_get_curve:
                fname = "rnp_key_get_curve"; ftype = typeof(Key_get_curve);
            break; case LibSymID.key_add_uid:
                fname = "rnp_key_add_uid"; ftype = typeof(Key_add_uid);
            break; case LibSymID.key_get_fprint:
                fname = "rnp_key_get_fprint"; ftype = typeof(Key_get_fprint);
            break; case LibSymID.key_get_keyid:
                fname = "rnp_key_get_keyid"; ftype = typeof(Key_get_keyid);
            break; case LibSymID.key_get_grip:
                fname = "rnp_key_get_grip"; ftype = typeof(Key_get_grip);
            break; case LibSymID.key_get_primary_grip:
                fname = "rnp_key_get_primary_grip"; ftype = typeof(Key_get_primary_grip);
            break; case LibSymID.key_get_primary_fprint:
                fname = "rnp_key_get_primary_fprint"; ftype = typeof(Key_get_primary_fprint);
            break; case LibSymID.key_allows_usage:
                fname = "rnp_key_allows_usage"; ftype = typeof(Key_allows_usage);
            break; case LibSymID.key_get_creation:
                fname = "rnp_key_get_creation"; ftype = typeof(Key_get_creation);
            break; case LibSymID.key_get_expiration:
                fname = "rnp_key_get_expiration"; ftype = typeof(Key_get_expiration);
            break; case LibSymID.key_set_expiration:
                fname = "rnp_key_set_expiration"; ftype = typeof(Key_set_expiration);
            break; case LibSymID.key_is_valid:
                fname = "rnp_key_is_valid"; ftype = typeof(Key_is_valid);
            break; case LibSymID.key_valid_till:
                fname = "rnp_key_valid_till"; ftype = typeof(Key_valid_till);
            break; case LibSymID.key_is_revoked:
                fname = "rnp_key_is_revoked"; ftype = typeof(Key_is_revoked);
            break; case LibSymID.key_get_revocation_reason:
                fname = "rnp_key_get_revocation_reason"; ftype = typeof(Key_get_revocation_reason);
            break; case LibSymID.key_is_superseded:
                fname = "rnp_key_is_superseded"; ftype = typeof(Key_is_superseded);
            break; case LibSymID.key_is_compromised:
                fname = "rnp_key_is_compromised"; ftype = typeof(Key_is_compromised);
            break; case LibSymID.key_is_retired:
                fname = "rnp_key_is_retired"; ftype = typeof(Key_is_retired);
            break; case LibSymID.key_is_locked:
                fname = "rnp_key_is_locked"; ftype = typeof(Key_is_locked);
            break; case LibSymID.key_get_protection_type:
                fname = "rnp_key_get_protection_type"; ftype = typeof(Key_get_protection_type);
            break; case LibSymID.key_get_protection_mode:
                fname = "rnp_key_get_protection_mode"; ftype = typeof(Key_get_protection_mode);
            break; case LibSymID.key_get_protection_cipher:
                fname = "rnp_key_get_protection_cipher"; ftype = typeof(Key_get_protection_cipher);
            break; case LibSymID.key_get_protection_hash:
                fname = "rnp_key_get_protection_hash"; ftype = typeof(Key_get_protection_hash);
            break; case LibSymID.key_get_protection_iterations:
                fname = "rnp_key_get_protection_iterations"; ftype = typeof(Key_get_protection_iterations);
            break; case LibSymID.key_lock:
                fname = "rnp_key_lock"; ftype = typeof(Key_lock);
            break; case LibSymID.key_unlock:
                fname = "rnp_key_unlock"; ftype = typeof(Key_unlock);
            break; case LibSymID.key_is_protected:
                fname = "rnp_key_is_protected"; ftype = typeof(Key_is_protected);
            break; case LibSymID.key_protect:
                fname = "rnp_key_protect"; ftype = typeof(Key_protect);
            break; case LibSymID.key_unprotect:
                fname = "rnp_key_unprotect"; ftype = typeof(Key_unprotect);
            break; case LibSymID.key_is_primary:
                fname = "rnp_key_is_primary"; ftype = typeof(Key_is_primary);
            break; case LibSymID.key_is_sub:
                fname = "rnp_key_is_sub"; ftype = typeof(Key_is_sub);
            break; case LibSymID.key_have_secret:
                fname = "rnp_key_have_secret"; ftype = typeof(Key_have_secret);
            break; case LibSymID.key_have_public:
                fname = "rnp_key_have_public"; ftype = typeof(Key_have_public);
            break; case LibSymID.key_packets_to_json:
                fname = "rnp_key_packets_to_json"; ftype = typeof(Key_packets_to_json);
            break; case LibSymID.dump_packets_to_json:
                fname = "rnp_dump_packets_to_json"; ftype = typeof(Dump_packets_to_json);
            break; case LibSymID.dump_packets_to_output:
                fname = "rnp_dump_packets_to_output"; ftype = typeof(Dump_packets_to_output);
            break; case LibSymID.op_sign_create:
                fname = "rnp_op_sign_create"; ftype = typeof(Op_sign_create);
            break; case LibSymID.op_sign_cleartext_create:
                fname = "rnp_op_sign_cleartext_create"; ftype = typeof(Op_sign_cleartext_create);
            break; case LibSymID.op_sign_detached_create:
                fname = "rnp_op_sign_detached_create"; ftype = typeof(Op_sign_detached_create);
            break; case LibSymID.op_sign_add_signature:
                fname = "rnp_op_sign_add_signature"; ftype = typeof(Op_sign_add_signature);
            break; case LibSymID.op_sign_signature_set_hash:
                fname = "rnp_op_sign_signature_set_hash"; ftype = typeof(Op_sign_signature_set_hash);
            break; case LibSymID.op_sign_signature_set_creation_time:
                fname = "rnp_op_sign_signature_set_creation_time"; ftype = typeof(Op_sign_signature_set_creation_time);
            break; case LibSymID.op_sign_signature_set_expiration_time:
                fname = "rnp_op_sign_signature_set_expiration_time"; ftype = typeof(Op_sign_signature_set_expiration_time);
            break; case LibSymID.op_sign_set_compression:
                fname = "rnp_op_sign_set_compression"; ftype = typeof(Op_sign_set_compression);
            break; case LibSymID.op_sign_set_armor:
                fname = "rnp_op_sign_set_armor"; ftype = typeof(Op_sign_set_armor);
            break; case LibSymID.op_sign_set_hash:
                fname = "rnp_op_sign_set_hash"; ftype = typeof(Op_sign_set_hash);
            break; case LibSymID.op_sign_set_creation_time:
                fname = "rnp_op_sign_set_creation_time"; ftype = typeof(Op_sign_set_creation_time);
            break; case LibSymID.op_sign_set_expiration_time:
                fname = "rnp_op_sign_set_expiration_time"; ftype = typeof(Op_sign_set_expiration_time);
            break; case LibSymID.op_sign_set_file_name:
                fname = "rnp_op_sign_set_file_name"; ftype = typeof(Op_sign_set_file_name);
            break; case LibSymID.op_sign_set_file_mtime:
                fname = "rnp_op_sign_set_file_mtime"; ftype = typeof(Op_sign_set_file_mtime);
            break; case LibSymID.op_sign_execute:
                fname = "rnp_op_sign_execute"; ftype = typeof(Op_sign_execute);
            break; case LibSymID.op_sign_destroy:
                fname = "rnp_op_sign_destroy"; ftype = typeof(Op_sign_destroy);
            break; case LibSymID.op_verify_create:
                fname = "rnp_op_verify_create"; ftype = typeof(Op_verify_create);
            break; case LibSymID.op_verify_detached_create:
                fname = "rnp_op_verify_detached_create"; ftype = typeof(Op_verify_detached_create);
            break; case LibSymID.op_verify_execute:
                fname = "rnp_op_verify_execute"; ftype = typeof(Op_verify_execute);
            break; case LibSymID.op_verify_get_signature_count:
                fname = "rnp_op_verify_get_signature_count"; ftype = typeof(Op_verify_get_signature_count);
            break; case LibSymID.op_verify_get_signature_at:
                fname = "rnp_op_verify_get_signature_at"; ftype = typeof(Op_verify_get_signature_at);
            break; case LibSymID.op_verify_get_file_info:
                fname = "rnp_op_verify_get_file_info"; ftype = typeof(Op_verify_get_file_info);
            break; case LibSymID.op_verify_get_protection_info:
                fname = "rnp_op_verify_get_protection_info"; ftype = typeof(Op_verify_get_protection_info);
            break; case LibSymID.op_verify_get_recipient_count:
                fname = "rnp_op_verify_get_recipient_count"; ftype = typeof(Op_verify_get_recipient_count);
            break; case LibSymID.op_verify_get_used_recipient:
                fname = "rnp_op_verify_get_used_recipient"; ftype = typeof(Op_verify_get_used_recipient);
            break; case LibSymID.op_verify_get_recipient_at:
                fname = "rnp_op_verify_get_recipient_at"; ftype = typeof(Op_verify_get_recipient_at);
            break; case LibSymID.recipient_get_keyid:
                fname = "rnp_recipient_get_keyid"; ftype = typeof(Recipient_get_keyid);
            break; case LibSymID.recipient_get_alg:
                fname = "rnp_recipient_get_alg"; ftype = typeof(Recipient_get_alg);
            break; case LibSymID.op_verify_get_symenc_count:
                fname = "rnp_op_verify_get_symenc_count"; ftype = typeof(Op_verify_get_symenc_count);
            break; case LibSymID.op_verify_get_used_symenc:
                fname = "rnp_op_verify_get_used_symenc"; ftype = typeof(Op_verify_get_used_symenc);
            break; case LibSymID.op_verify_get_symenc_at:
                fname = "rnp_op_verify_get_symenc_at"; ftype = typeof(Op_verify_get_symenc_at);
            break; case LibSymID.symenc_get_cipher:
                fname = "rnp_symenc_get_cipher"; ftype = typeof(Symenc_get_cipher);
            break; case LibSymID.symenc_get_aead_alg:
                fname = "rnp_symenc_get_aead_alg"; ftype = typeof(Symenc_get_aead_alg);
            break; case LibSymID.symenc_get_hash_alg:
                fname = "rnp_symenc_get_hash_alg"; ftype = typeof(Symenc_get_hash_alg);
            break; case LibSymID.symenc_get_s2k_type:
                fname = "rnp_symenc_get_s2k_type"; ftype = typeof(Symenc_get_s2k_type);
            break; case LibSymID.symenc_get_s2k_iterations:
                fname = "rnp_symenc_get_s2k_iterations"; ftype = typeof(Symenc_get_s2k_iterations);
            break; case LibSymID.op_verify_destroy:
                fname = "rnp_op_verify_destroy"; ftype = typeof(Op_verify_destroy);
            break; case LibSymID.op_verify_signature_get_status:
                fname = "rnp_op_verify_signature_get_status"; ftype = typeof(Op_verify_signature_get_status);
            break; case LibSymID.op_verify_signature_get_handle:
                fname = "rnp_op_verify_signature_get_handle"; ftype = typeof(Op_verify_signature_get_handle);
            break; case LibSymID.op_verify_signature_get_hash:
                fname = "rnp_op_verify_signature_get_hash"; ftype = typeof(Op_verify_signature_get_hash);
            break; case LibSymID.op_verify_signature_get_key:
                fname = "rnp_op_verify_signature_get_key"; ftype = typeof(Op_verify_signature_get_key);
            break; case LibSymID.op_verify_signature_get_times:
                fname = "rnp_op_verify_signature_get_times"; ftype = typeof(Op_verify_signature_get_times);
            break; case LibSymID.buffer_destroy:
                fname = "rnp_buffer_destroy"; ftype = typeof(Buffer_destroy);
            break; case LibSymID.input_from_path:
                fname = "rnp_input_from_path"; ftype = typeof(Input_from_path);
            break; case LibSymID.input_from_memory:
                fname = "rnp_input_from_memory"; ftype = typeof(Input_from_memory);
            break; case LibSymID.input_from_callback:
                fname = "rnp_input_from_callback"; ftype = typeof(Input_from_callback);
            break; case LibSymID.input_destroy:
                fname = "rnp_input_destroy"; ftype = typeof(Input_destroy);
            break; case LibSymID.output_to_path:
                fname = "rnp_output_to_path"; ftype = typeof(Output_to_path);
            break; case LibSymID.output_to_file:
                fname = "rnp_output_to_file"; ftype = typeof(Output_to_file);
            break; case LibSymID.output_to_memory:
                fname = "rnp_output_to_memory"; ftype = typeof(Output_to_memory);
            break; case LibSymID.output_to_armor:
                fname = "rnp_output_to_armor"; ftype = typeof(Output_to_armor);
            break; case LibSymID.output_memory_get_buf:
                fname = "rnp_output_memory_get_buf"; ftype = typeof(Output_memory_get_buf);
            break; case LibSymID.output_to_callback:
                fname = "rnp_output_to_callback"; ftype = typeof(Output_to_callback);
            break; case LibSymID.output_to_null:
                fname = "rnp_output_to_null"; ftype = typeof(Output_to_null);
            break; case LibSymID.output_write:
                fname = "rnp_output_write"; ftype = typeof(Output_write);
            break; case LibSymID.output_finish:
                fname = "rnp_output_finish"; ftype = typeof(Output_finish);
            break; case LibSymID.output_destroy:
                fname = "rnp_output_destroy"; ftype = typeof(Output_destroy);
            break; case LibSymID.op_encrypt_create:
                fname = "rnp_op_encrypt_create"; ftype = typeof(Op_encrypt_create);
            break; case LibSymID.op_encrypt_add_recipient:
                fname = "rnp_op_encrypt_add_recipient"; ftype = typeof(Op_encrypt_add_recipient);
            break; case LibSymID.op_encrypt_add_signature:
                fname = "rnp_op_encrypt_add_signature"; ftype = typeof(Op_encrypt_add_signature);
            break; case LibSymID.op_encrypt_set_hash:
                fname = "rnp_op_encrypt_set_hash"; ftype = typeof(Op_encrypt_set_hash);
            break; case LibSymID.op_encrypt_set_creation_time:
                fname = "rnp_op_encrypt_set_creation_time"; ftype = typeof(Op_encrypt_set_creation_time);
            break; case LibSymID.op_encrypt_set_expiration_time:
                fname = "rnp_op_encrypt_set_expiration_time"; ftype = typeof(Op_encrypt_set_expiration_time);
            break; case LibSymID.op_encrypt_add_password:
                fname = "rnp_op_encrypt_add_password"; ftype = typeof(Op_encrypt_add_password);
            break; case LibSymID.op_encrypt_set_armor:
                fname = "rnp_op_encrypt_set_armor"; ftype = typeof(Op_encrypt_set_armor);
            break; case LibSymID.op_encrypt_set_cipher:
                fname = "rnp_op_encrypt_set_cipher"; ftype = typeof(Op_encrypt_set_cipher);
            break; case LibSymID.op_encrypt_set_aead:
                fname = "rnp_op_encrypt_set_aead"; ftype = typeof(Op_encrypt_set_aead);
            break; case LibSymID.op_encrypt_set_aead_bits:
                fname = "rnp_op_encrypt_set_aead_bits"; ftype = typeof(Op_encrypt_set_aead_bits);
            break; case LibSymID.op_encrypt_set_compression:
                fname = "rnp_op_encrypt_set_compression"; ftype = typeof(Op_encrypt_set_compression);
            break; case LibSymID.op_encrypt_set_file_name:
                fname = "rnp_op_encrypt_set_file_name"; ftype = typeof(Op_encrypt_set_file_name);
            break; case LibSymID.op_encrypt_set_file_mtime:
                fname = "rnp_op_encrypt_set_file_mtime"; ftype = typeof(Op_encrypt_set_file_mtime);
            break; case LibSymID.op_encrypt_execute:
                fname = "rnp_op_encrypt_execute"; ftype = typeof(Op_encrypt_execute);
            break; case LibSymID.op_encrypt_destroy:
                fname = "rnp_op_encrypt_destroy"; ftype = typeof(Op_encrypt_destroy);
            break; case LibSymID.decrypt:
                fname = "rnp_decrypt"; ftype = typeof(Decrypt);
            break; case LibSymID.get_public_key_data:
                fname = "rnp_get_public_key_data"; ftype = typeof(Get_public_key_data);
            break; case LibSymID.get_secret_key_data:
                fname = "rnp_get_secret_key_data"; ftype = typeof(Get_secret_key_data);
            break; case LibSymID.key_to_json:
                fname = "rnp_key_to_json"; ftype = typeof(Key_to_json);
            break; case LibSymID.identifier_iterator_create:
                fname = "rnp_identifier_iterator_create"; ftype = typeof(Identifier_iterator_create);
            break; case LibSymID.identifier_iterator_next:
                fname = "rnp_identifier_iterator_next"; ftype = typeof(Identifier_iterator_next);
            break; case LibSymID.identifier_iterator_destroy:
                fname = "rnp_identifier_iterator_destroy"; ftype = typeof(Identifier_iterator_destroy);
            break; case LibSymID.output_pipe:
                fname = "rnp_output_pipe"; ftype = typeof(Output_pipe);
            break; case LibSymID.output_armor_set_line_length:
                fname = "rnp_output_armor_set_line_length"; ftype = typeof(Output_armor_set_line_length);
            break;
            }
            if(NativeLibrary.TryGetExport(lib, fname, out symb)) {
                fx = Marshal.GetDelegateForFunctionPointer(symb, ftype);
                libSymbols.Add(symbol, fx);
            } else
                throw new EntryPointNotFoundException("Missing method " + fname);
        }
        return fx;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void Rop_get_key_cb(IntPtr ffi, IntPtr app_ctx, IntPtr identifier_type, IntPtr identifier, bool secret);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool Rop_password_cb(IntPtr ffi, IntPtr app_ctx, IntPtr key, IntPtr pgp_context, IntPtr buf, uint buf_len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool Rop_input_reader(IntPtr app_ctx, IntPtr buf, long len, ref long read);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void Rop_input_closer(IntPtr app_ctx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool Rop_output_writer(IntPtr app_ctx, IntPtr buf, long len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void Rop_output_closer(IntPtr app_ctx, bool discard);

    public static void KeyCallback(IntPtr ffi, IntPtr app_ctx, IntPtr identifier_type, IntPtr identifier, bool secret) {
        if(app_ctx == IntPtr.Zero)
            return;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;

        RopHandle sffi = new RopHandle(ffi);
        RopHandle sidentifier_type = new RopHandle(identifier_type, true);
        RopHandle sidentifier = new RopHandle(identifier, true);
        cb.KeyCB(sffi, sidentifier_type, sidentifier, secret);
    }

    public static bool PassCallback(IntPtr ffi, IntPtr app_ctx, IntPtr key, IntPtr pgp_context, IntPtr buf, uint buf_len) {
        if(app_ctx == IntPtr.Zero)
            return false;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;

        RopHandle sffi = new RopHandle(ffi);
        RopHandle skey = new RopHandle(key);
        RopHandle spgp_context = new RopHandle(pgp_context, true);
        RopHandle sbuf = new RopHandle(buf);
        return cb.PassCB(sffi, skey, spgp_context, sbuf, (int)buf_len);
    }

    static bool InputReadCallback(IntPtr app_ctx, IntPtr buf, long len, ref long read) {
        if(app_ctx == IntPtr.Zero)
            return false;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;

        RopHandle sbuf = new RopHandle(buf);
        read = cb.InReadCB(sbuf, len);
        return read >= 0;
    }

    static void InputCloseCallback(IntPtr app_ctx) {
        if(app_ctx == IntPtr.Zero)
            return;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;

        cb.InCloseCB();
    }

    static bool OutputWriteCallback(IntPtr app_ctx, IntPtr buf, long len) {
        if(app_ctx == IntPtr.Zero)
            return false;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;
        
        RopHandle sbuf = new RopHandle(buf);
        return cb.OutWriteCB(sbuf, len);
    }

    static void OutputCloseCallback(IntPtr app_ctx, bool discard) {
        if(app_ctx == IntPtr.Zero)
            return;
        RopCB cb = (RopCB)GCHandle.FromIntPtr(app_ctx).Target;
        
        cb.OutCloseCB(discard);
    }

    private Rop_get_key_cb keyCallback = new Rop_get_key_cb(KeyCallback);
    private Rop_password_cb passCallback = new Rop_password_cb(PassCallback);
    private Rop_input_reader inputReadCallback = new Rop_input_reader(InputReadCallback);
    private Rop_input_closer inputCloseCallback = new Rop_input_closer(InputCloseCallback);
    private Rop_output_writer outputWriteCallback = new Rop_output_writer(OutputWriteCallback);
    private Rop_output_closer outputCloseCallback = new Rop_output_closer(OutputCloseCallback);
    
    public string rnp_result_to_string(uint result) {
        return Marshal.PtrToStringUTF8(((Result_to_string)FFIFunction(LibSymID.result_to_string))(result));
    }

    public string rnp_version_string() {
        return Marshal.PtrToStringUTF8(((Version_string)FFIFunction(LibSymID.version_string))());
    }

    public string rnp_version_string_full() {
        return Marshal.PtrToStringUTF8(((Version_string_full)FFIFunction(LibSymID.version_string_full))());
    }

    public uint rnp_version() {
        return ((Version)FFIFunction(LibSymID.version))();
    }

    public uint rnp_version_for(uint major, uint minor, uint patch) {
        return ((Version_for)FFIFunction(LibSymID.version_for))(major, minor, patch);
    }

    public uint rnp_version_major(uint version) {
        return ((Version_major)FFIFunction(LibSymID.version_major))(version);
    }

    public uint rnp_version_minor(uint version) {
        return ((Version_minor)FFIFunction(LibSymID.version_minor))(version);
    }

    public uint rnp_version_patch(uint version) {
        return ((Version_patch)FFIFunction(LibSymID.version_patch))(version);
    }

    public ulong rnp_version_commit_timestamp() {
        return ((Version_commit_timestamp)FFIFunction(LibSymID.version_commit_timestamp))();
    }

    public uint rnp_enable_debug(object file) {
        var enc = Encode(file);
        uint ret = ((Enable_debug)FFIFunction(LibSymID.enable_debug))(enc.P);
        FreeEncoded(enc);
        return ret;
    }

    public uint rnp_disable_debug() {
        return ((Disable_debug)FFIFunction(LibSymID.disable_debug))();
    }

    //F(ffi: [cd], pub_format: str, sec_format: str) -> int
    public uint rnp_ffi_create(out RopHandle ffi, object pub_format, object sec_format) {
        var cffi = IntPtr.Zero;
        var encs = new[] { Encode(pub_format), Encode(sec_format) };
        uint ret = ((Ffi_create)FFIFunction(LibSymID.ffi_create))(ref cffi, encs[0].P, encs[1].P);
        FreeEncoded(encs);
        ffi = new RopHandle(cffi);
        return ret;
    }

    //F(ffi: cd) -> int
    public uint rnp_ffi_destroy(IntPtr ffi) {
        uint ret = ((Ffi_destroy)FFIFunction(LibSymID.ffi_destroy))(ffi);
        ClearCallbacks(new RopHandle(ffi));
        return ret;
    }
    
    //F(ffi: cd, fd_: int) -> int
    public uint rnp_ffi_set_log_fd(IntPtr ffi, int fd) {
        return ((Ffi_set_log_fd)FFIFunction(LibSymID.ffi_set_log_fd))(ffi, fd);
    }

    //F(ffi: cd, getkeycb: Rop_get_key_cb, getkeycb_ctx: obj) -> int
    public uint rnp_ffi_set_key_provider(IntPtr ffi, RopKeyCallBack getkeycb, object getkeycb_ctx) {
        RopHandle hffi = new RopHandle(ffi);
        RopCB cb = (getkeycb!=null? new RopCB(RopCB.Type.KEY, hffi, getkeycb_ctx, getkeycb) : null);
        if(cb != null)
            cb.nhnd = GCHandle.Alloc(cb);
        uint ret = ((Ffi_set_key_provider)FFIFunction(LibSymID.ffi_set_key_provider))(ffi, keyCallback, cb!=null? GCHandle.ToIntPtr(cb.nhnd) : IntPtr.Zero);
        if(cb != null) {
            RopCB[] cbs = null;
            if(!h2cb.TryGetValue(hffi, out cbs) || cbs == null)
                h2cb[hffi] = cbs = new RopCB[2];
            cbs[0] = cb;
        }
        return ret;
    }

    //F(ffi: cd, getpasscb: Rop_password_cb, getpasscb_ctx: obj) -> int
    public uint rnp_ffi_set_pass_provider(IntPtr ffi, RopPassCallBack getpasscb, object getpasscb_ctx) {
        RopHandle hffi = new RopHandle(ffi);
        RopCB cb = (getpasscb!=null? new RopCB(RopCB.Type.PASS, hffi, getpasscb_ctx, getpasscb) : null);
        if(cb != null)
            cb.nhnd = GCHandle.Alloc(cb);
        uint ret = ((Ffi_set_pass_provider)FFIFunction(LibSymID.ffi_set_pass_provider))(ffi, passCallback, cb!=null? GCHandle.ToIntPtr(cb.nhnd) : IntPtr.Zero);
        if(cb != null) {
            RopCB[] cbs = null;
            if(!h2cb.TryGetValue(hffi, out cbs) || cbs == null)
                h2cb[hffi] = cbs = new RopCB[2];
            cbs[1] = cb;
        }
        return ret;
    }

    //F(homedir: [cd]) -> int
    public uint rnp_get_default_homedir(out RopHandle homedir) {
        var ptr = IntPtr.Zero;
        uint ret = ((Get_default_homedir)FFIFunction(LibSymID.get_default_homedir))(ref ptr);
        homedir = new RopHandle(ptr, true);
        return ret;
    }

    //F(homedir: str, pub_format: [cd], pub_path: [cd], sec_format: [cd], sec_path: [cd]) -> int
    public uint rnp_detect_homedir_info(object homedir, out RopHandle pub_format, out RopHandle pub_path, out RopHandle sec_format, out RopHandle sec_path) {
        var ptrs = new[] { IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero };
        var enc = Encode(homedir);
        uint ret = ((Detect_homedir_info)FFIFunction(LibSymID.detect_homedir_info))(enc.P, ref ptrs[0], ref ptrs[1], ref ptrs[2], ref ptrs[3]);
        FreeEncoded(enc);
        pub_format = new RopHandle(ptrs[0], true);
        pub_path = new RopHandle(ptrs[1], true);
        sec_format = new RopHandle(ptrs[2], true);
        sec_path = new RopHandle(ptrs[3], true);
        return ret;
    }

    //F(buf: str, buf_len: int, format_: [cd]) -> int
    public uint rnp_detect_key_format(object buf, long buf_len, out RopHandle format) {
        var enc = Encode(buf, (int)buf_len);
        IntPtr cformat = IntPtr.Zero;
        uint ret = ((Detect_key_format)FFIFunction(LibSymID.detect_key_format))(enc.P, enc.Len, ref cformat);
        format = new RopHandle(cformat, true);
        FreeEncoded(enc);
        return ret;
    }

    //F(hash_: str, msec: int, iterations: [int]) -> int
    public uint rnp_calculate_iterations(object hash, long msec, out int iterations) {
        var enc = Encode(hash);
        IntPtr iters = IntPtr.Zero;
        uint ret = ((Calculate_iterations)FFIFunction(LibSymID.calculate_iterations))(enc.P, msec, ref iters);
        FreeEncoded(enc);
        iterations = iters.ToInt32();
        return ret;
    }

    //F(type_: str, name: str, supported: [bool]) -> int
    public uint rnp_supports_feature(object type, object name, out bool supported) {
        var csupported = IntPtr.Zero;
        var encs = new[] { Encode(type), Encode(name) };
        uint ret = ((Supports_feature)FFIFunction(LibSymID.supports_feature))(encs[0].P, encs[1].P, ref csupported);
        FreeEncoded(encs);
        supported = (csupported.ToInt32()!=0);
        return ret;
    }

    //F(type_: str, result: [cd]) -> int
    public uint rnp_supported_features(object type, out RopHandle result) {
        var enc = Encode(type);
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Supported_features)FFIFunction(LibSymID.supported_features))(enc.P, ref cresult);
        result = new RopHandle(cresult, true);
        FreeEncoded(enc);
        return ret;
    }

    //F(ffi: cd, key: cd, context: str, password: [cd]) -> int
    public uint rnp_request_password(IntPtr ffi, IntPtr key, object context, out RopHandle password) {
        var enc = Encode(context);
        IntPtr cpass = IntPtr.Zero;
        uint ret = ((Request_password)FFIFunction(LibSymID.request_password))(ffi, key, enc.P, ref cpass);
        password = new RopHandle(cpass, true);
        FreeEncoded(enc);
        return ret;
    }

    //F(ffi: cd, format_: str, input_: cd, flags: int) -> int
    public uint rnp_load_keys(IntPtr ffi, object format, IntPtr input, uint flags) {
        var enc = Encode(format);
        uint ret = ((Load_keys)FFIFunction(LibSymID.load_keys))(ffi, enc.P, input, flags);
        FreeEncoded(enc);
        return ret;
    }

    //F(ffi: cd, flags: int) -> int
    public uint rnp_unload_keys(IntPtr ffi, uint flags) {
        uint ret = ((Unload_keys)FFIFunction(LibSymID.unload_keys))(ffi, flags);
        return ret;
    }

    //F(ffi: cd, input_: cd, flags: int, results: [cd]) -> int
    public uint rnp_import_keys(IntPtr ffi, IntPtr input, uint flags, out RopHandle results) {
        IntPtr cres = IntPtr.Zero;
        uint ret = ((Import_keys)FFIFunction(LibSymID.import_keys))(ffi, input, flags, ref cres);
        results = new RopHandle(cres, true);
        return ret;
    }

    //F(ffi: cd, input_: cd, flags: int, results: [cd]) -> int
    public uint rnp_import_signatures(IntPtr ffi, IntPtr input, uint flags, out RopHandle results) {
        IntPtr cres = IntPtr.Zero;
        uint ret = ((Import_signatures)FFIFunction(LibSymID.import_signatures))(ffi, input, flags, ref cres);
        results = new RopHandle(cres, true);
        return ret;
    }

    //F(ffi: cd, format_: str, output: cd, flags: int) -> int
    public uint rnp_save_keys(IntPtr ffi, object format, IntPtr output, uint flags) {
        var enc = Encode(format);
        uint ret = ((Save_keys)FFIFunction(LibSymID.save_keys))(ffi, enc.P, output, flags);
        FreeEncoded(enc);
        return ret;
    }

    //F(ffi: cd, count: [int]) -> int
    public uint rnp_get_public_key_count(IntPtr ffi, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Get_public_key_count)FFIFunction(LibSymID.get_public_key_count))(ffi, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(ffi: cd, count: [int]) -> int
    public uint rnp_get_secret_key_count(IntPtr ffi, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Get_secret_key_count)FFIFunction(LibSymID.get_secret_key_count))(ffi, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(ffi: cd, identifier_type: str, identifier: str, key: [cd]) -> int
    public uint rnp_locate_key(IntPtr ffi, object identifier_type, object identifier, out RopHandle key) {
        var encs = new[] { Encode(identifier_type), Encode(identifier) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Locate_key)FFIFunction(LibSymID.locate_key))(ffi, encs[0].P, encs[1].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(key: cd) -> int
    public uint rnp_key_handle_destroy(IntPtr key) {
        return ((Key_handle_destroy)FFIFunction(LibSymID.key_handle_destroy))(key);
    }

    //F(ffi: cd, json: str, results: [cd]) -> int
    public uint rnp_generate_key_json(IntPtr ffi, object json, out RopHandle results) {
        var enc = Encode(json);
        IntPtr cres = IntPtr.Zero;
        uint ret = ((Generate_key_json)FFIFunction(LibSymID.generate_key_json))(ffi, enc.P, ref cres);
        FreeEncoded(enc);
        results = new RopHandle(cres, true);
        return ret;
    }

    //F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_rsa(IntPtr ffi, uint bits, uint subbits, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_rsa)FFIFunction(LibSymID.generate_key_rsa))(ffi, bits, subbits, encs[0].P, encs[1].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_dsa_eg(IntPtr ffi, uint bits, uint subbits, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_dsa_eg)FFIFunction(LibSymID.generate_key_dsa_eg))(ffi, bits, subbits, encs[0].P, encs[1].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(ffi: cd, curve: str, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_ec(IntPtr ffi, object curve, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(curve), Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_ec)FFIFunction(LibSymID.generate_key_ec))(ffi, encs[0].P, encs[1].P, encs[2].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(ffi: cd, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_25519(IntPtr ffi, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_25519)FFIFunction(LibSymID.generate_key_25519))(ffi, encs[0].P, encs[1].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(ffi: cd, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_sm2(IntPtr ffi, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_sm2)FFIFunction(LibSymID.generate_key_sm2))(ffi, encs[0].P, encs[1].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(ffi: cd, key_alg: str, sub_alg: str, key_bits: int, sub_bits: int, key_curve: str, sub_curve: str, userid: str, password: str, key: [cd]) -> int
    public uint rnp_generate_key_ex(IntPtr ffi, object key_alg, object sub_alg, uint key_bits, uint sub_bits, object key_curve, object sub_curve, object userid, object password, out RopHandle key) {
        var encs = new[] { Encode(key_alg), Encode(sub_alg), Encode(key_curve), Encode(sub_curve), Encode(userid), Encode(password) };
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Generate_key_ex)FFIFunction(LibSymID.generate_key_ex))(ffi, encs[0].P, encs[1].P, key_bits, sub_bits, encs[2].P, encs[3].P, encs[4].P, encs[5].P, ref ckey);
        FreeEncoded(encs);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(op_: [cd], ffi: cd, alg: str) -> int
    public uint rnp_op_generate_create(out RopHandle op, IntPtr ffi, object alg) {
        var enc = Encode(alg);
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_generate_create)FFIFunction(LibSymID.op_generate_create))(ref cop, ffi, enc.P);
        FreeEncoded(enc);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: [cd], ffi: cd, primary: cd, alg: str) -> int
    public uint rnp_op_generate_subkey_create(out RopHandle op, IntPtr ffi, IntPtr primary, object alg) {
        var enc = Encode(alg);
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_generate_subkey_create)FFIFunction(LibSymID.op_generate_subkey_create))(ref cop, ffi, primary, enc.P);
        FreeEncoded(enc);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: cd, bits: int) -> int
    public uint rnp_op_generate_set_bits(IntPtr op, uint bits) {
        return ((Op_generate_set_bits)FFIFunction(LibSymID.op_generate_set_bits))(op, bits);
    }

    //F(op_: cd, hash_: str) -> int
    public uint rnp_op_generate_set_hash(IntPtr op, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_generate_set_hash)FFIFunction(LibSymID.op_generate_set_hash))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, qbits: int) -> int
    public uint rnp_op_generate_set_dsa_qbits(IntPtr op, uint qbits) {
        return ((Op_generate_set_dsa_qbits)FFIFunction(LibSymID.op_generate_set_dsa_qbits))(op, qbits);
    }

    //F(op_: cd, curve: str) -> int
    public uint rnp_op_generate_set_curve(IntPtr op, object curve) {
        var enc = Encode(curve);
        uint ret = ((Op_generate_set_curve)FFIFunction(LibSymID.op_generate_set_curve))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, password: str) -> int
    public uint rnp_op_generate_set_protection_password(IntPtr op, object password) {
        var enc = Encode(password);
        uint ret = ((Op_generate_set_protection_password)FFIFunction(LibSymID.op_generate_set_protection_password))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, request: bool) -> int
    public uint rnp_op_generate_set_request_password(IntPtr op, bool request) {
        return ((Op_generate_set_request_password)FFIFunction(LibSymID.op_generate_set_request_password))(op, request);
    }

    //F(op_: cd, cipher: str) -> int
    public uint rnp_op_generate_set_protection_cipher(IntPtr op, object cipher) {
        var enc = Encode(cipher);
        uint ret = ((Op_generate_set_protection_cipher)FFIFunction(LibSymID.op_generate_set_protection_cipher))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, hash_: str) -> int
    public uint rnp_op_generate_set_protection_hash(IntPtr op, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_generate_set_protection_hash)FFIFunction(LibSymID.op_generate_set_protection_hash))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, mode: str) -> int
    public uint rnp_op_generate_set_protection_mode(IntPtr op, object mode) {
        var enc = Encode(mode);
        uint ret = ((Op_generate_set_protection_mode)FFIFunction(LibSymID.op_generate_set_protection_mode))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, iterations: int) -> int
    public uint rnp_op_generate_set_protection_iterations(IntPtr op, uint iterations) {
        return ((Op_generate_set_protection_iterations)FFIFunction(LibSymID.op_generate_set_protection_iterations))(op, iterations);
    }

    //F(op_: cd, usage: str) -> int
    public uint rnp_op_generate_add_usage(IntPtr op, object usage) {
        var enc = Encode(usage);
        uint ret = ((Op_generate_add_usage)FFIFunction(LibSymID.op_generate_add_usage))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_clear_usage(IntPtr op) {
        return ((Op_generate_clear_usage)FFIFunction(LibSymID.op_generate_clear_usage))(op);
    }

    //F(op_: cd, userid: str) -> int
    public uint rnp_op_generate_set_userid(IntPtr op, object userid) {
        var enc = Encode(userid);
        uint ret = ((Op_generate_set_userid)FFIFunction(LibSymID.op_generate_set_userid))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, expiration: int) -> int
    public uint rnp_op_generate_set_expiration(IntPtr op, uint expiration) {
        return ((Op_generate_set_expiration)FFIFunction(LibSymID.op_generate_set_expiration))(op, expiration);
    }

    //F(op_: cd, hash_: str) -> int
    public uint rnp_op_generate_add_pref_hash(IntPtr op, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_generate_add_pref_hash)FFIFunction(LibSymID.op_generate_add_pref_hash))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_clear_pref_hashes(IntPtr op) {
        return ((Op_generate_clear_pref_hashes)FFIFunction(LibSymID.op_generate_clear_pref_hashes))(op);
    }

    //F(op_: cd, compression: str) -> int
    public uint rnp_op_generate_add_pref_compression(IntPtr op, object compression) {
        var enc = Encode(compression);
        uint ret = ((Op_generate_add_pref_compression)FFIFunction(LibSymID.op_generate_add_pref_compression))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_clear_pref_compression(IntPtr op) {
        return ((Op_generate_clear_pref_compression)FFIFunction(LibSymID.op_generate_clear_pref_compression))(op);
    }

    //F(op_: cd, cipher: str) -> int
    public uint rnp_op_generate_add_pref_cipher(IntPtr op, object cipher) {
        var enc = Encode(cipher);
        uint ret = ((Op_generate_add_pref_cipher)FFIFunction(LibSymID.op_generate_add_pref_cipher))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_clear_pref_ciphers(IntPtr op) {
        return ((Op_generate_clear_pref_ciphers)FFIFunction(LibSymID.op_generate_clear_pref_ciphers))(op);
    }

    //F(op_: cd, keyserver: str) -> int
    public uint rnp_op_generate_set_pref_keyserver(IntPtr op, object keyserver) {
        var enc = Encode(keyserver);
        uint ret = ((Op_generate_set_pref_keyserver)FFIFunction(LibSymID.op_generate_set_pref_keyserver))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_execute(IntPtr op) {
        return ((Op_generate_execute)FFIFunction(LibSymID.op_generate_execute))(op);
    }

    //F(op_: cd, handle: [cd]) -> int
    public uint rnp_op_generate_get_key(IntPtr op, out RopHandle handle) {
        IntPtr chandle = IntPtr.Zero;
        uint ret = ((Op_generate_get_key)FFIFunction(LibSymID.op_generate_get_key))(op, ref chandle);
        handle = new RopHandle(chandle);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_generate_destroy(IntPtr op) {
        return ((Op_generate_destroy)FFIFunction(LibSymID.op_generate_destroy))(op);
    }

    //F(key: cd, output: cd, flags: int) -> int
    public uint rnp_key_export(IntPtr key, IntPtr output, uint flags) {
        return ((Key_export)FFIFunction(LibSymID.key_export))(key, output, flags);
    }
    
    //F(key: cd, subkey: cd, uid: str, output: cd, flags: int) -> int
    public uint rnp_key_export_autocrypt(IntPtr key, IntPtr subkey, object uid, IntPtr output, uint flags) {
        var enc = Encode(uid);
        uint ret = ((Key_export_autocrypt)FFIFunction(LibSymID.key_export_autocrypt))(key, subkey, enc.P, output, flags);
        FreeEncoded(enc);
        return ret;
    }
    
    //F(key: cd, output: cd, flags: int, hash: str, code: str, reason: str) -> int
    public uint rnp_key_export_revocation(IntPtr key, IntPtr output, uint flags, object hash, object code, object reason) {
        var encs = new[] { Encode(hash), Encode(code), Encode(reason) };
        uint ret = ((Key_export_revocation)FFIFunction(LibSymID.key_export_revocation))(key, output, flags, encs[0].P, encs[1].P, encs[2].P);
        FreeEncoded(encs);
        return ret;
    }

    //F(key: cd, flags: int, hash: str, code: str, reason: str) -> int
    public uint rnp_key_revoke(IntPtr key, uint flags, object hash, object code, object reason) {
        var encs = new[] { Encode(hash), Encode(code), Encode(reason) };
        uint ret = ((Key_revoke)FFIFunction(LibSymID.key_revoke))(key, flags, encs[0].P, encs[1].P, encs[2].P);
        FreeEncoded(encs);
        return ret;
    }

    //F(key: cd, flags: int) -> int
    public uint rnp_key_remove(IntPtr key, uint flags) {
        return ((Key_remove)FFIFunction(LibSymID.key_remove))(key, flags);
    }

    //F(input_: cd, contents: [cd]) -> int
    public uint rnp_guess_contents(IntPtr input, out RopHandle contents) {
        IntPtr ccont = IntPtr.Zero;
        uint ret = ((Guess_contents)FFIFunction(LibSymID.guess_contents))(input, ref ccont);
        contents = new RopHandle(ccont, true);
        return ret;
    }

    //F(input_: cd, output: cd, type_: str) -> int
    public uint rnp_enarmor(IntPtr input, IntPtr output, object type) {
        var enc = Encode(type);
        uint ret = ((Enarmor)FFIFunction(LibSymID.enarmor))(input, output, enc.P);
        FreeEncoded(enc);
        return ret;
    }
    
    //F(input_: cd, output: cd) -> int
    public uint rnp_dearmor(IntPtr input, IntPtr output) {
        return ((Dearmor)FFIFunction(LibSymID.dearmor))(input, output);
    }
    
    //F(key: cd, uid: [cd]) -> int
    public uint rnp_key_get_primary_uid(IntPtr key, out RopHandle uid) {
        IntPtr cuid = IntPtr.Zero;
        uint ret = ((Key_get_primary_uid)FFIFunction(LibSymID.key_get_primary_uid))(key, ref cuid);
        uid = new RopHandle(cuid, true);
        return ret;
    }

    //F(key: cd, count: [int]) -> int
    public uint rnp_key_get_uid_count(IntPtr key, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Key_get_uid_count)FFIFunction(LibSymID.key_get_uid_count))(key, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(key: cd, idx: int, uid: [cd]) -> int
    public uint rnp_key_get_uid_at(IntPtr key, uint idx, out RopHandle uid) {
        IntPtr cuid = IntPtr.Zero;
        uint ret = ((Key_get_uid_at)FFIFunction(LibSymID.key_get_uid_at))(key, idx, ref cuid);
        uid = new RopHandle(cuid, true);
        return ret;
    }

    //F(key: cd, idx: int, uid: [cd]) -> int
    public uint rnp_key_get_uid_handle_at(IntPtr key, uint idx, out RopHandle uid) {
        IntPtr cuid = IntPtr.Zero;
        uint ret = ((Key_get_uid_handle_at)FFIFunction(LibSymID.key_get_uid_handle_at))(key, idx, ref cuid);
        uid = new RopHandle(cuid);
        return ret;
    }

    //F(uid: cd, type: [int]) -> int
    public uint rnp_uid_get_type(IntPtr uid, out uint type) {
        IntPtr ctype = IntPtr.Zero;
        uint ret = ((Uid_get_type)FFIFunction(LibSymID.uid_get_type))(uid, ref ctype);
        type = (uint)ctype.ToInt64();
        return ret;
    }

    //F(uid: cd, data: [cd], size: [int]) -> int
    public uint rnp_uid_get_data(IntPtr uid, out RopHandle data, out long size) {
        IntPtr cdata = IntPtr.Zero;
        IntPtr csize = IntPtr.Zero;
        uint ret = ((Uid_get_data)FFIFunction(LibSymID.uid_get_data))(uid, ref cdata, ref csize);
        data = new RopHandle(cdata);
        size = csize.ToInt64();
        return ret;
    }

    //F(uid: cd, primary: [int]) -> int
    public uint rnp_uid_is_primary(IntPtr uid, out bool primary) {
        IntPtr cprimary = IntPtr.Zero;
        uint ret = ((Uid_is_primary)FFIFunction(LibSymID.uid_is_primary))(uid, ref cprimary);
        primary = (cprimary.ToInt32()!=0);
        return ret;
    }

    //F(uid: cd, valid: [int]) -> int
    public uint rnp_uid_is_valid(IntPtr uid, out bool valid) {
        IntPtr cvalid = IntPtr.Zero;
        uint ret = ((Uid_is_valid)FFIFunction(LibSymID.uid_is_valid))(uid, ref cvalid);
        valid = (cvalid.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, count: [int]) -> int
    public uint rnp_key_get_signature_count(IntPtr key, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Key_get_signature_count)FFIFunction(LibSymID.key_get_signature_count))(key, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(key: cd, idx: int, sig: [cd]) -> int
    public uint rnp_key_get_signature_at(IntPtr key, uint idx, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Key_get_signature_at)FFIFunction(LibSymID.key_get_signature_at))(key, idx, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(key: cd, sig: [cd]) -> int
    public uint rnp_key_get_revocation_signature(IntPtr key, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Key_get_revocation_signature)FFIFunction(LibSymID.key_get_revocation_signature))(key, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(uid: cd, count: [int]) -> int
    public uint rnp_uid_get_signature_count(IntPtr uid, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Uid_get_signature_count)FFIFunction(LibSymID.uid_get_signature_count))(uid, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(uid: cd, idx: int, sig: [cd]) -> int
    public uint rnp_uid_get_signature_at(IntPtr uid, uint idx, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Uid_get_signature_at)FFIFunction(LibSymID.uid_get_signature_at))(uid, idx, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(uid: cd, sig: [cd]) -> int
    public uint rnp_signature_get_type(IntPtr sig, out RopHandle type) {
        IntPtr ctype = IntPtr.Zero;
        uint ret = ((Signature_get_type)FFIFunction(LibSymID.signature_get_type))(sig, ref ctype);
        type = new RopHandle(ctype, true);
        return ret;
    }

    //F(sig: cd, alg: [cd]) -> int
    public uint rnp_signature_get_alg(IntPtr sig, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Signature_get_alg)FFIFunction(LibSymID.signature_get_alg))(sig, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(sig: cd, alg: [cd]) -> int
    public uint rnp_signature_get_hash_alg(IntPtr sig, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Signature_get_hash_alg)FFIFunction(LibSymID.signature_get_hash_alg))(sig, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(sig: cd, create: [int]) -> int
    public uint rnp_signature_get_creation(IntPtr sig, out uint create) {
        IntPtr ccreate = IntPtr.Zero;
        uint ret = ((Signature_get_creation)FFIFunction(LibSymID.signature_get_creation))(sig, ref ccreate);
        create = (uint)ccreate.ToInt64();
        return ret;
    }

    //F(sig: cd, result: [cd]) -> int
    public uint rnp_signature_get_keyid(IntPtr sig, out RopHandle result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Signature_get_keyid)FFIFunction(LibSymID.signature_get_keyid))(sig, ref cresult);
        result = new RopHandle(cresult, true);
        return ret;
    }

    //F(sig: cd, key: [cd]) -> int
    public uint rnp_signature_get_signer(IntPtr sig, out RopHandle key) {
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Signature_get_signer)FFIFunction(LibSymID.signature_get_signer))(sig, ref ckey);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(sig: cd, flags: int) -> int
    public uint rnp_signature_is_valid(IntPtr sig, uint flags) {
        return ((Signature_is_valid)FFIFunction(LibSymID.signature_is_valid))(sig, flags);
    }

    //F(sig: cd, flags: int, json: [cd]) -> int
    public uint rnp_signature_packet_to_json(IntPtr sig, uint flags, out RopHandle json) {
        IntPtr cjson = IntPtr.Zero;
        uint ret = ((Signature_packet_to_json)FFIFunction(LibSymID.signature_packet_to_json))(sig, flags, ref cjson);
        json = new RopHandle(cjson, true);
        return ret;
    }

    //F(sig: cd) -> int
    public uint rnp_signature_handle_destroy(IntPtr sig) {
        return ((Signature_handle_destroy)FFIFunction(LibSymID.signature_handle_destroy))(sig);
    }

    //F(uid: cd, result: [bool]) -> int
    public uint rnp_uid_is_revoked(IntPtr uid, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Uid_is_revoked)FFIFunction(LibSymID.uid_is_revoked))(uid, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(uid: cd, sig: [cd]) -> int
    public uint rnp_uid_get_revocation_signature(IntPtr uid, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Uid_get_revocation_signature)FFIFunction(LibSymID.uid_get_revocation_signature))(uid, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }
    
    //F(uid: cd) -> int
    public uint rnp_uid_handle_destroy(IntPtr uid) {
        return ((Uid_handle_destroy)FFIFunction(LibSymID.uid_handle_destroy))(uid);
    }

    //F(key: cd, count: [int]) -> int
    public uint rnp_key_get_subkey_count(IntPtr key, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Key_get_subkey_count)FFIFunction(LibSymID.key_get_subkey_count))(key, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(key: cd, idx: int, subkey: [cd]) -> int
    public uint rnp_key_get_subkey_at(IntPtr key, uint idx, out RopHandle subkey) {
        IntPtr csubkey = IntPtr.Zero;
        uint ret = ((Key_get_subkey_at)FFIFunction(LibSymID.key_get_subkey_at))(key, idx, ref csubkey);
        subkey = new RopHandle(csubkey);
        return ret;
    }

    //F(key: cd, alg: [cd]) -> int
    public uint rnp_key_get_alg(IntPtr key, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Key_get_alg)FFIFunction(LibSymID.key_get_alg))(key, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(key: cd, bits: [int]) -> int
    public uint rnp_key_get_bits(IntPtr key, out uint bits) {
        IntPtr cbits = IntPtr.Zero;
        uint ret = ((Key_get_bits)FFIFunction(LibSymID.key_get_bits))(key, ref cbits);
        bits = (uint)cbits.ToInt32();
        return ret;
    }

    //F(key: cd, qbits: [int]) -> int
    public uint rnp_key_get_dsa_qbits(IntPtr key, out uint qbits) {
        IntPtr cqbits = IntPtr.Zero;
        uint ret = ((Key_get_dsa_qbits)FFIFunction(LibSymID.key_get_dsa_qbits))(key, ref cqbits);
        qbits = (uint)cqbits.ToInt32();
        return ret;
    }

    //F(key: cd, curve: [cd]) -> int
    public uint rnp_key_get_curve(IntPtr key, out RopHandle curve) {
        IntPtr ccurve = IntPtr.Zero;
        uint ret = ((Key_get_curve)FFIFunction(LibSymID.key_get_curve))(key, ref ccurve);
        curve = new RopHandle(ccurve, true);
        return ret;
    }

    //F(key: cd, uid: str, hash_: str, expiration: int, key_flags: int, primary: bool) -> int
    public uint rnp_key_add_uid(IntPtr key, object uid, object hash, uint expiration, uint key_flags, bool primary) {
        var encs = new[] { Encode(uid), Encode(hash) };
        uint ret = ((Key_add_uid)FFIFunction(LibSymID.key_add_uid))(key, encs[0].P, encs[1].P, expiration, key_flags, primary);
        FreeEncoded(encs);
        return ret;
    }

    //F(key: cd, fprint: [cd]) -> int
    public uint rnp_key_get_fprint(IntPtr key, out RopHandle fprint) {
        IntPtr cfprint = IntPtr.Zero;
        uint ret = ((Key_get_fprint)FFIFunction(LibSymID.key_get_fprint))(key, ref cfprint);
        fprint = new RopHandle(cfprint, true);
        return ret;
    }

    //F(key: cd, keyid: [cd]) -> int
    public uint rnp_key_get_keyid(IntPtr key, out RopHandle keyid) {
        IntPtr ckeyid = IntPtr.Zero;
        uint ret = ((Key_get_keyid)FFIFunction(LibSymID.key_get_keyid))(key, ref ckeyid);
        keyid = new RopHandle(ckeyid, true);
        return ret;
    }

    //F(key: cd, grip: [cd]) -> int
    public uint rnp_key_get_grip(IntPtr key, out RopHandle grip) {
        IntPtr cgrip = IntPtr.Zero;
        uint ret = ((Key_get_grip)FFIFunction(LibSymID.key_get_grip))(key, ref cgrip);
        grip = new RopHandle(cgrip, true);
        return ret;
    }

    //F(key: cd, grip: [cd]) -> int
    public uint rnp_key_get_primary_grip(IntPtr key, out RopHandle grip) {
        IntPtr cgrip = IntPtr.Zero;
        uint ret = ((Key_get_primary_grip)FFIFunction(LibSymID.key_get_primary_grip))(key, ref cgrip);
        grip = new RopHandle(cgrip, true);
        return ret;
    }

    //F(key: cd, fprint: [cd]) -> int
    public uint rnp_key_get_primary_fprint(IntPtr key, out RopHandle fprint) {
        IntPtr cprint = IntPtr.Zero;
        uint ret = ((Key_get_primary_fprint)FFIFunction(LibSymID.key_get_primary_fprint))(key, ref cprint);
        fprint = new RopHandle(cprint, true);
        return ret;
    }

    //F(key: cd, usage: str, result: [bool]) -> int
    public uint rnp_key_allows_usage(IntPtr key, object usage, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        var enc = Encode(usage);
        uint ret = ((Key_allows_usage)FFIFunction(LibSymID.key_allows_usage))(key, enc.P, ref cresult);
        FreeEncoded(enc);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [int]) -> int
    public uint rnp_key_get_creation(IntPtr key, out uint result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_get_creation)FFIFunction(LibSymID.key_get_creation))(key, ref cresult);
        result = (uint)cresult.ToInt64();
        return ret;
    }

    //F(key: cd, result: [int]) -> int
    public uint rnp_key_get_expiration(IntPtr key, out uint result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_get_expiration)FFIFunction(LibSymID.key_get_expiration))(key, ref cresult);
        result = (uint)cresult.ToInt64();
        return ret;
    }

    //F(key: cd, expiry: int) -> int
    public uint rnp_key_set_expiration(IntPtr key, uint expiry) {
        return ((Key_set_expiration)FFIFunction(LibSymID.key_set_expiration))(key, expiry);
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_valid(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_valid)FFIFunction(LibSymID.key_is_valid))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [int]) -> int
    public uint rnp_key_valid_till(IntPtr key, out uint result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_valid_till)FFIFunction(LibSymID.key_valid_till))(key, ref cresult);
        result = (uint)cresult.ToInt64();
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_revoked(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_revoked)FFIFunction(LibSymID.key_is_revoked))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [cd]) -> int
    public uint rnp_key_get_revocation_reason(IntPtr key, out RopHandle result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_get_revocation_reason)FFIFunction(LibSymID.key_get_revocation_reason))(key, ref cresult);
        result = new RopHandle(cresult, true);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_superseded(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_superseded)FFIFunction(LibSymID.key_is_superseded))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_compromised(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_compromised)FFIFunction(LibSymID.key_is_compromised))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_retired(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_retired)FFIFunction(LibSymID.key_is_retired))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_locked(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_locked)FFIFunction(LibSymID.key_is_locked))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, type: [str]) -> int
    public uint rnp_key_get_protection_type(IntPtr key, out RopHandle type) {
        IntPtr ctype = IntPtr.Zero;
        uint ret = ((Key_get_protection_type)FFIFunction(LibSymID.key_get_protection_type))(key, ref ctype);
        type = new RopHandle(ctype, true);
        return ret;
    }

    //F(key: cd, type: [str]) -> int
    public uint rnp_key_get_protection_mode(IntPtr key, out RopHandle cipher) {
        IntPtr ccipher = IntPtr.Zero;
        uint ret = ((Key_get_protection_mode)FFIFunction(LibSymID.key_get_protection_mode))(key, ref ccipher);
        cipher = new RopHandle(ccipher, true);
        return ret;
    }

    //F(key: cd, type: [str]) -> int
    public uint rnp_key_get_protection_cipher(IntPtr key, out RopHandle cipher) {
        IntPtr ccipher = IntPtr.Zero;
        uint ret = ((Key_get_protection_cipher)FFIFunction(LibSymID.key_get_protection_cipher))(key, ref ccipher);
        cipher = new RopHandle(ccipher, true);
        return ret;
    }

    //F(key: cd, type: [str]) -> int
    public uint rnp_key_get_protection_hash(IntPtr key, out RopHandle hash) {
        IntPtr chash = IntPtr.Zero;
        uint ret = ((Key_get_protection_hash)FFIFunction(LibSymID.key_get_protection_hash))(key, ref chash);
        hash = new RopHandle(chash, true);
        return ret;
    }

    //F(key: cd, type: [int]) -> int
    public uint rnp_key_get_protection_iterations(IntPtr key, out uint iterations) {
        IntPtr citers = IntPtr.Zero;
        uint ret = ((Key_get_protection_iterations)FFIFunction(LibSymID.key_get_protection_iterations))(key, ref citers);
        iterations = (uint)citers.ToInt32();
        return ret;
    }
    
    //F(key: cd) -> int
    public uint rnp_key_lock(IntPtr key) {
        return ((Key_lock)FFIFunction(LibSymID.key_lock))(key);
    }

    //F(key: cd, password: str) -> int
    public uint rnp_key_unlock(IntPtr key, object password) {
        var enc = Encode(password);
        uint ret = ((Key_unlock)FFIFunction(LibSymID.key_unlock))(key, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_protected(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_protected)FFIFunction(LibSymID.key_is_protected))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(handle: cd, password: str, cipher: str, cipher_mode: str, hash_: str, iterations: int) -> int
    public uint rnp_key_protect(IntPtr handle, object password, object cipher, object cipher_mode, object hash, uint iterations) {
        var encs = new[] { Encode(password), Encode(cipher), Encode(cipher_mode), Encode(hash) };
        uint ret = ((Key_protect)FFIFunction(LibSymID.key_protect))(handle, encs[0].P, encs[1].P, encs[2].P, encs[3].P, iterations);
        FreeEncoded(encs);
        return ret;
    }

    //F(key: cd, password: str) -> int
    public uint rnp_key_unprotect(IntPtr key, object password) {
        var enc = Encode(password);
        uint ret = ((Key_unprotect)FFIFunction(LibSymID.key_unprotect))(key, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_primary(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_primary)FFIFunction(LibSymID.key_is_primary))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_is_sub(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_is_sub)FFIFunction(LibSymID.key_is_sub))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_have_secret(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_have_secret)FFIFunction(LibSymID.key_have_secret))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, result: [bool]) -> int
    public uint rnp_key_have_public(IntPtr key, out bool result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_have_public)FFIFunction(LibSymID.key_have_public))(key, ref cresult);
        result = (cresult.ToInt32()!=0);
        return ret;
    }

    //F(key: cd, secret: bool, flags: int, result: [cd]) -> int
    public uint rnp_key_packets_to_json(IntPtr key, bool secret, uint flags, out RopHandle result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_packets_to_json)FFIFunction(LibSymID.key_packets_to_json))(key, secret, flags, ref cresult);
        result = new RopHandle(cresult, true);
        return ret;
    }

    //F(input_: cd, flags: int, result: [cd]) -> int
    public uint rnp_dump_packets_to_json(IntPtr input, uint flags, out RopHandle result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Dump_packets_to_json)FFIFunction(LibSymID.dump_packets_to_json))(input, flags, ref cresult);
        result = new RopHandle(cresult, true);
        return ret;
    }

    //F(input_: cd, output: cd, flags: int) -> int
    public uint rnp_dump_packets_to_output(IntPtr input, IntPtr output, uint flags) {
        return ((Dump_packets_to_output)FFIFunction(LibSymID.dump_packets_to_output))(input, output, flags);
    }

    //F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
    public uint rnp_op_sign_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr output) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_sign_create)FFIFunction(LibSymID.op_sign_create))(ref cop, ffi, input, output);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
    public uint rnp_op_sign_cleartext_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr output) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_sign_cleartext_create)FFIFunction(LibSymID.op_sign_cleartext_create))(ref cop, ffi, input, output);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
    public uint rnp_op_sign_detached_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr signature) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_sign_detached_create)FFIFunction(LibSymID.op_sign_detached_create))(ref cop, ffi, input, signature);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: cd, key: cd, sig: [cd]) -> int
    public uint rnp_op_sign_add_signature(IntPtr op, IntPtr key, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Op_sign_add_signature)FFIFunction(LibSymID.op_sign_add_signature))(op, key, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(sig: cd, hash_: str) -> int
    public uint rnp_op_sign_signature_set_hash(IntPtr sig, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_sign_signature_set_hash)FFIFunction(LibSymID.op_sign_signature_set_hash))(sig, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(sig: cd, create: int) -> int
    public uint rnp_op_sign_signature_set_creation_time(IntPtr sig, uint create) {
        return ((Op_sign_signature_set_creation_time)FFIFunction(LibSymID.op_sign_signature_set_creation_time))(sig, create);
    }

    //F(sig: cd, expires: int) -> int
    public uint rnp_op_sign_signature_set_expiration_time(IntPtr sig, uint expires) {
        return ((Op_sign_signature_set_expiration_time)FFIFunction(LibSymID.op_sign_signature_set_expiration_time))(sig, expires);
    }

    //F(op_: cd, compression: str, level: int) -> int
    public uint rnp_op_sign_set_compression(IntPtr op, object compression, int level) {
        var enc = Encode(compression);
        uint ret = ((Op_sign_set_compression)FFIFunction(LibSymID.op_sign_set_compression))(op, enc.P, level);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, armored: bool) -> int
    public uint rnp_op_sign_set_armor(IntPtr op, bool armored) {
        return ((Op_sign_set_armor)FFIFunction(LibSymID.op_sign_set_armor))(op, armored);
    }

    //F(op_: cd, hash_: str) -> int
    public uint rnp_op_sign_set_hash(IntPtr op, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_sign_set_hash)FFIFunction(LibSymID.op_sign_set_hash))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, create: int) -> int
    public uint rnp_op_sign_set_creation_time(IntPtr op, uint create) {
        return ((Op_sign_set_creation_time)FFIFunction(LibSymID.op_sign_set_creation_time))(op, create);
    }

    //F(op_: cd, expire: int) -> int
    public uint rnp_op_sign_set_expiration_time(IntPtr op, uint expire) {
        return ((Op_sign_set_expiration_time)FFIFunction(LibSymID.op_sign_set_expiration_time))(op, expire);
    }

    //F(op_: cd, filename: str) -> int
    public uint rnp_op_sign_set_file_name(IntPtr op, object filename) {
        var enc = Encode(filename);
        uint ret = ((Op_sign_set_file_name)FFIFunction(LibSymID.op_sign_set_file_name))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, mtime: int) -> int
    public uint rnp_op_sign_set_file_mtime(IntPtr op, uint mtime) {
        return ((Op_sign_set_file_mtime)FFIFunction(LibSymID.op_sign_set_file_mtime))(op, mtime);
    }

    //F(op_: cd) -> int
    public uint rnp_op_sign_execute(IntPtr op) {
        return ((Op_sign_execute)FFIFunction(LibSymID.op_sign_execute))(op);
    }

    //F(op_: cd) -> int
    public uint rnp_op_sign_destroy(IntPtr op) {
        return ((Op_sign_destroy)FFIFunction(LibSymID.op_sign_destroy))(op);
    }

    //F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
    public uint rnp_op_verify_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr output) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_verify_create)FFIFunction(LibSymID.op_verify_create))(ref cop, ffi, input, output);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
    public uint rnp_op_verify_detached_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr signature) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_verify_detached_create)FFIFunction(LibSymID.op_verify_detached_create))(ref cop, ffi, input, signature);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_verify_execute(IntPtr op) {
        return ((Op_verify_execute)FFIFunction(LibSymID.op_verify_execute))(op);
    }

    //F(op_: cd, count: [int]) -> int
    public uint rnp_op_verify_get_signature_count(IntPtr op, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Op_verify_get_signature_count)FFIFunction(LibSymID.op_verify_get_signature_count))(op, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(op_: cd, idx: int, sig: [cd]) -> int
    public uint rnp_op_verify_get_signature_at(IntPtr op, uint idx, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Op_verify_get_signature_at)FFIFunction(LibSymID.op_verify_get_signature_at))(op, idx, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(op_: cd, filename: [cd], mtime: [int]) -> int
    public uint rnp_op_verify_get_file_info(IntPtr op, out RopHandle filename, out uint mtime) {
        IntPtr cfilename = IntPtr.Zero, cmtime = IntPtr.Zero;
        uint ret = ((Op_verify_get_file_info)FFIFunction(LibSymID.op_verify_get_file_info))(op, ref cfilename, ref cmtime);
        filename = new RopHandle(cfilename, true);
        mtime = (uint)cmtime.ToInt64();
        return ret;
    }

    //F(op: cd, mode: [str], cipher: [str], valid: [bool]) -> int
    public uint rnp_op_verify_get_protection_info(IntPtr op, out RopHandle mode, out RopHandle cipher, out bool valid) {
        IntPtr cmode = IntPtr.Zero, ccipher = IntPtr.Zero, cvalid = IntPtr.Zero;
        uint ret = ((Op_verify_get_protection_info)FFIFunction(LibSymID.op_verify_get_protection_info))(op, ref cmode, ref ccipher, ref cvalid);
        mode = new RopHandle(cmode, true);
        cipher = new RopHandle(ccipher, true);
        valid = (cvalid.ToInt32()!=0);
        return ret;
    }

    //F(op: cd, count: [int]) -> int
    public uint rnp_op_verify_get_recipient_count(IntPtr op, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Op_verify_get_recipient_count)FFIFunction(LibSymID.op_verify_get_recipient_count))(op, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(op: cd, recipient: [cd]) -> int
    public uint rnp_op_verify_get_used_recipient(IntPtr op, out RopHandle recipient) {
        IntPtr crecip = IntPtr.Zero;
        uint ret = ((Op_verify_get_used_recipient)FFIFunction(LibSymID.op_verify_get_used_recipient))(op, ref crecip);
        recipient = new RopHandle(crecip);
        return ret;
    }

    //F(op: cd, idx: int, recipient: [cd]) -> int
    public uint rnp_op_verify_get_recipient_at(IntPtr op, uint idx, out RopHandle recipient) {
        IntPtr crecip = IntPtr.Zero;
        uint ret = ((Op_verify_get_recipient_at)FFIFunction(LibSymID.op_verify_get_recipient_at))(op, idx, ref crecip);
        recipient = new RopHandle(crecip);
        return ret;
    }

    //F(recipient: cd, keyid: [str]) -> int
    public uint rnp_recipient_get_keyid(IntPtr recipient, out RopHandle keyid) {
        IntPtr ckeyid = IntPtr.Zero;
        uint ret = ((Recipient_get_keyid)FFIFunction(LibSymID.recipient_get_keyid))(recipient, ref ckeyid);
        keyid = new RopHandle(ckeyid, true);
        return ret;
    }

    //F(recipient: cd, alg: [str]) -> int
    public uint rnp_recipient_get_alg(IntPtr recipient, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Recipient_get_alg)FFIFunction(LibSymID.recipient_get_alg))(recipient, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(op: cd, count: [int]) -> int
    public uint rnp_op_verify_get_symenc_count(IntPtr op, out uint count) {
        IntPtr ccount = IntPtr.Zero;
        uint ret = ((Op_verify_get_symenc_count)FFIFunction(LibSymID.op_verify_get_symenc_count))(op, ref ccount);
        count = (uint)ccount.ToInt32();
        return ret;
    }

    //F(op: cd, symenc: [cd]) -> int
    public uint rnp_op_verify_get_used_symenc(IntPtr op, out RopHandle symenc) {
        IntPtr csymenc = IntPtr.Zero;
        uint ret = ((Op_verify_get_used_symenc)FFIFunction(LibSymID.op_verify_get_used_symenc))(op, ref csymenc);
        symenc = new RopHandle(csymenc);
        return ret;
    }

    //F(op: cd, idx: int, symenc: [cd]) -> int
    public uint rnp_op_verify_get_symenc_at(IntPtr op, uint idx, out RopHandle symenc) {
        IntPtr csymenc = IntPtr.Zero;
        uint ret = ((Op_verify_get_symenc_at)FFIFunction(LibSymID.op_verify_get_symenc_at))(op, idx, ref csymenc);
        symenc = new RopHandle(csymenc);
        return ret;
    }

    //F(symenc: cd, cipher: [str]) -> int
    public uint rnp_symenc_get_cipher(IntPtr symenc, out RopHandle cipher) {
        IntPtr ccipher = IntPtr.Zero;
        uint ret = ((Symenc_get_cipher)FFIFunction(LibSymID.symenc_get_cipher))(symenc, ref ccipher);
        cipher = new RopHandle(ccipher, true);
        return ret;
    }

    //F(symenc: cd, alg: [str]) -> int
    public uint rnp_symenc_get_aead_alg(IntPtr symenc, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Symenc_get_aead_alg)FFIFunction(LibSymID.symenc_get_aead_alg))(symenc, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(symenc: cd, alg: [str]) -> int
    public uint rnp_symenc_get_hash_alg(IntPtr symenc, out RopHandle alg) {
        IntPtr calg = IntPtr.Zero;
        uint ret = ((Symenc_get_hash_alg)FFIFunction(LibSymID.symenc_get_hash_alg))(symenc, ref calg);
        alg = new RopHandle(calg, true);
        return ret;
    }

    //F(symenc: cd, type: [str]) -> int
    public uint rnp_symenc_get_s2k_type(IntPtr symenc, out RopHandle type) {
        IntPtr ctype = IntPtr.Zero;
        uint ret = ((Symenc_get_s2k_type)FFIFunction(LibSymID.symenc_get_s2k_type))(symenc, ref ctype);
        type = new RopHandle(ctype, true);
        return ret;
    }

    //F(symenc: cd, iterations: [int]) -> int
    public uint rnp_symenc_get_s2k_iterations(IntPtr symenc, out uint iterations) {
        IntPtr citer = IntPtr.Zero;
        uint ret = ((Symenc_get_s2k_iterations)FFIFunction(LibSymID.symenc_get_s2k_iterations))(symenc, ref citer);
        iterations = (uint)citer.ToInt32();
        return ret;
    }

    //F(op_: cd) -> int
    public uint rnp_op_verify_destroy(IntPtr op) {
        return ((Op_verify_destroy)FFIFunction(LibSymID.op_verify_destroy))(op);
    }

    //F(sig: cd) -> int
    public uint rnp_op_verify_signature_get_status(IntPtr sig) {
        return ((Op_verify_signature_get_status)FFIFunction(LibSymID.op_verify_signature_get_status))(sig);
    }

    //F(sig: cd, handle: [cd]) -> int
    public uint rnp_op_verify_signature_get_handle(IntPtr sig, out RopHandle handle) {
        IntPtr chandle = IntPtr.Zero;
        uint ret = ((Op_verify_signature_get_handle)FFIFunction(LibSymID.op_verify_signature_get_handle))(sig, ref chandle);
        handle = new RopHandle(chandle);
        return ret;
    }

    //F(sig: cd, hash_: [cd]) -> int
    public uint rnp_op_verify_signature_get_hash(IntPtr sig, out RopHandle hash) {
        IntPtr chash = IntPtr.Zero;
        uint ret = ((Op_verify_signature_get_hash)FFIFunction(LibSymID.op_verify_signature_get_hash))(sig, ref chash);
        hash = new RopHandle(chash, true);
        return ret;
    }

    //F(sig: cd, key: [cd]) -> int
    public uint rnp_op_verify_signature_get_key(IntPtr sig, out RopHandle key) {
        IntPtr ckey = IntPtr.Zero;
        uint ret = ((Op_verify_signature_get_key)FFIFunction(LibSymID.op_verify_signature_get_key))(sig, ref ckey);
        key = new RopHandle(ckey);
        return ret;
    }

    //F(sig: cd, create: [int], expires: [int]) -> int
    public uint rnp_op_verify_signature_get_times(IntPtr sig, out uint create, out uint expires) {
        IntPtr ccreate = IntPtr.Zero, cexpires = IntPtr.Zero;
        uint ret = ((Op_verify_signature_get_times)FFIFunction(LibSymID.op_verify_signature_get_times))(sig, ref ccreate, ref cexpires);
        create = (uint)ccreate.ToInt64();
        expires = (uint)cexpires.ToInt64();
        return ret;
    }

    //F(ptr: cd)
    public void rnp_buffer_destroy(IntPtr ptr) {
        ((Buffer_destroy)FFIFunction(LibSymID.buffer_destroy))(ptr);
    }

    //F(input_: [cd], path: str) -> int
    public uint rnp_input_from_path(out RopHandle input, object path) {
        IntPtr cinput = IntPtr.Zero;
        var enc = Encode(path);
        uint ret = ((Input_from_path)FFIFunction(LibSymID.input_from_path))(ref cinput, enc.P);
        FreeEncoded(enc);
        input = new RopHandle(cinput);
        return ret;
    }

    //F(input_: [cd], buf: bstr, buf_len: int, do_copy: bool) -> int
    public uint rnp_input_from_memory(out RopHandle input, object buf, uint buf_len, bool do_copy) {
        IntPtr cinput = IntPtr.Zero;
        var enc = Encode(buf, (int)buf_len);
        uint ret = ((Input_from_memory)FFIFunction(LibSymID.input_from_memory))(ref cinput, enc.P, enc.Len, do_copy);
        input = new RopHandle(cinput);
        if(cinput != IntPtr.Zero) {
            RopHandle ebh = new RopHandle(enc.P);
            ebh.source = enc.Item3;
            retainsI.Add(input, ebh);
        } else
            FreeEncoded(enc);
        return ret;
    }

    //F(input_: [cd], reader: Rop_input_reader_t, closer: Rop_input_closer_t, app_ctx: obj) -> int
    public uint rnp_input_from_callback(out RopHandle input, RopInputCallBack callBack, object app_ctx) {
        RopCB icb = (callBack!=null? new RopCB(RopCB.Type.INPUT, null, app_ctx, callBack) : null);
        if(icb != null)
            icb.nhnd = GCHandle.Alloc(icb);
        IntPtr cinput = IntPtr.Zero;
        uint ret = ((Input_from_callback)FFIFunction(LibSymID.input_from_callback))(ref cinput, inputReadCallback, inputCloseCallback, icb!=null? GCHandle.ToIntPtr(icb.nhnd) : IntPtr.Zero);
        input = new RopHandle(cinput);
        if(icb != null) {
            if(input != null && !input.IsNull()) {
                icb.hnd = input;
                h2cb[input] = new RopCB[] {icb};
            } else
                icb.nhnd.Free();
        }
        return ret;
    }

    //F(input_: cd) -> int
    public uint rnp_input_destroy(IntPtr input) {
        uint ret = ((Input_destroy)FFIFunction(LibSymID.input_destroy))(input);
        var hi = new RopHandle(input);
        if(retainsI.TryGetValue(hi, out RopHandle rt) && rt != null) {
            rt.source = IntPtr.Zero;
            retainsI.Remove(hi);
        }
        ClearCallbacks(new RopHandle(input));
        return ret;
    }

    //F(output: [cd], path: str) -> int
    public uint rnp_output_to_path(out RopHandle output, object path) {
        IntPtr coutput = IntPtr.Zero;
        var enc = Encode(path);
        uint ret = ((Output_to_path)FFIFunction(LibSymID.output_to_path))(ref coutput, enc.P);
        FreeEncoded(enc);
        output = new RopHandle(coutput);
        return ret;
    }

    //F(output: [cd], path: str, flags: int) -> int
    public uint rnp_output_to_file(out RopHandle output, object path, uint flags) {
        IntPtr coutput = IntPtr.Zero;
        var enc = Encode(path);
        uint ret = ((Output_to_file)FFIFunction(LibSymID.output_to_file))(ref coutput, enc.P, flags);
        FreeEncoded(enc);
        output = new RopHandle(coutput);
        return ret;
    }

    //F(output: [cd], max_alloc: int) -> int
    public uint rnp_output_to_memory(out RopHandle output, long max_alloc) {
        IntPtr coutput = IntPtr.Zero;
        uint ret = ((Output_to_memory)FFIFunction(LibSymID.output_to_memory))(ref coutput, max_alloc);
        output = new RopHandle(coutput);
        return ret;
    }

    //F(base: cd, output: [cd], type_: str) -> int
    public uint rnp_output_to_armor(IntPtr _base, out RopHandle output, object type) {
        IntPtr coutput = IntPtr.Zero;
        var enc = Encode(type);
        uint ret = ((Output_to_armor)FFIFunction(LibSymID.output_to_armor))(_base, ref coutput, enc.P);
        FreeEncoded(enc);
        output = new RopHandle(coutput);
        return ret;
    }

    //F(output: cd, buf: [cd], len_: [int], do_copy: bool) -> int
    public uint rnp_output_memory_get_buf(IntPtr output, out RopHandle buf, out long len, bool do_copy) {
        IntPtr cbuf = IntPtr.Zero;
        IntPtr clen = IntPtr.Zero;
        uint ret = ((Output_memory_get_buf)FFIFunction(LibSymID.output_memory_get_buf))(output, ref cbuf, ref clen, do_copy);
        buf = new RopHandle(cbuf);
        len = clen.ToInt64();
        return ret;
    }

    //F(output: [cd], writer: Rop_output_writer_t, closer: Rop_output_closer_t, app_ctx: obj) -> int
    public uint rnp_output_to_callback(out RopHandle output, RopOutputCallBack callBack, object app_ctx) {
        RopCB ocb = (callBack!=null? new RopCB(RopCB.Type.OUTPUT, null, app_ctx, callBack) : null);
        if(ocb != null)
            ocb.nhnd = GCHandle.Alloc(ocb);

        IntPtr coutput = IntPtr.Zero;
        uint ret = ((Output_to_callback)FFIFunction(LibSymID.output_to_callback))(ref coutput, outputWriteCallback, outputCloseCallback, ocb!=null? GCHandle.ToIntPtr(ocb.nhnd) : IntPtr.Zero);
        output = new RopHandle(coutput);
        if(ocb != null) {
            if(output != null && !output.IsNull()) {
                ocb.hnd = output;
                h2cb[output] = new RopCB[] {ocb};
            } else
                ocb.nhnd.Free();
        }
        return ret;
    }

    //F(output: [cd]) -> int
    public uint rnp_output_to_null(out RopHandle output) {
        IntPtr coutput = IntPtr.Zero;
        uint ret = ((Output_to_null)FFIFunction(LibSymID.output_to_null))(ref coutput);
        output = new RopHandle(coutput);
        return ret;
    }

    //F(output: cd, data: obj, size: int, written: [int]) -> int
    public uint rnp_output_write(IntPtr output, object data, long size, out long written) {
        IntPtr cwritten = IntPtr.Zero;
        var enc = Encode(data, (int)size);
        uint ret = ((Output_write)FFIFunction(LibSymID.output_write))(output, enc.P, enc.Len, ref cwritten);
        FreeEncoded(enc);
        written = cwritten.ToInt64();
        return ret;
    }

    //F(output: cd) -> int
    public uint rnp_output_finish(IntPtr output) {
        return ((Output_finish)FFIFunction(LibSymID.output_finish))(output);
    }

    //F(output: cd) -> int
    public uint rnp_output_destroy(IntPtr output) {
        uint ret = ((Output_destroy)FFIFunction(LibSymID.output_destroy))(output);
        ClearCallbacks(new RopHandle(output));
        return ret;
    }

    //F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
    public uint rnp_op_encrypt_create(out RopHandle op, IntPtr ffi, IntPtr input, IntPtr output) {
        IntPtr cop = IntPtr.Zero;
        uint ret = ((Op_encrypt_create)FFIFunction(LibSymID.op_encrypt_create))(ref cop, ffi, input, output);
        op = new RopHandle(cop);
        return ret;
    }

    //F(op_: cd, key: cd) -> int
    public uint rnp_op_encrypt_add_recipient(IntPtr op, IntPtr key) {
        return ((Op_encrypt_add_recipient)FFIFunction(LibSymID.op_encrypt_add_recipient))(op, key);
    }

    //F(op_: cd, key: cd, sig: [cd]) -> int
    public uint rnp_op_encrypt_add_signature(IntPtr op, IntPtr key, out RopHandle sig) {
        IntPtr csig = IntPtr.Zero;
        uint ret = ((Op_encrypt_add_signature)FFIFunction(LibSymID.op_encrypt_add_signature))(op, key, ref csig);
        sig = new RopHandle(csig);
        return ret;
    }

    //F(op_: cd, hash_: str) -> int
    public uint rnp_op_encrypt_set_hash(IntPtr op, object hash) {
        var enc = Encode(hash);
        uint ret = ((Op_encrypt_set_hash)FFIFunction(LibSymID.op_encrypt_set_hash))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, create: int) -> int
    public uint rnp_op_encrypt_set_creation_time(IntPtr op, uint create) {
        return ((Op_encrypt_set_creation_time)FFIFunction(LibSymID.op_encrypt_set_creation_time))(op, create);
    }

    //F(op_: cd, expire: int) -> int
    public uint rnp_op_encrypt_set_expiration_time(IntPtr op, uint expire) {
        return ((Op_encrypt_set_expiration_time)FFIFunction(LibSymID.op_encrypt_set_expiration_time))(op, expire);
    }

    //F(op_: cd, password: str, s2k_hash: str, iterations: int,
    public uint rnp_op_encrypt_add_password(IntPtr op, object password, object s2k_hash, uint iterations, object s2k_cipher) {
        var encs = new[] { Encode(password), Encode(s2k_hash), Encode(s2k_cipher) };
        uint ret = ((Op_encrypt_add_password)FFIFunction(LibSymID.op_encrypt_add_password))(op, encs[0].P, encs[1].P, iterations, encs[2].P);
        FreeEncoded(encs);
        return ret;
    }

    //F(op_: cd, armored: bool) -> int
    public uint rnp_op_encrypt_set_armor(IntPtr op, bool armored) {
        return ((Op_encrypt_set_armor)FFIFunction(LibSymID.op_encrypt_set_armor))(op, armored);
    }

    //F(op_: cd, cipher: str) -> int
    public uint rnp_op_encrypt_set_cipher(IntPtr op, object cipher) {
        var enc = Encode(cipher);
        uint ret = ((Op_encrypt_set_cipher)FFIFunction(LibSymID.op_encrypt_set_cipher))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, alg: str) -> int
    public uint rnp_op_encrypt_set_aead(IntPtr op, object alg) {
        var enc = Encode(alg);
        uint ret = ((Op_encrypt_set_aead)FFIFunction(LibSymID.op_encrypt_set_aead))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, bits: int) -> int
    public uint rnp_op_encrypt_set_aead_bits(IntPtr op, uint bits) {
        return ((Op_encrypt_set_aead_bits)FFIFunction(LibSymID.op_encrypt_set_aead_bits))(op, bits);
    }

    //F(op_: cd, compression str, level: int) -> int
    public uint rnp_op_encrypt_set_compression(IntPtr op, object compression, int level) {
        var enc = Encode(compression);
        uint ret = ((Op_encrypt_set_compression)FFIFunction(LibSymID.op_encrypt_set_compression))(op, enc.P, level);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, filename: str) -> int
    public uint rnp_op_encrypt_set_file_name(IntPtr op, object filename) {
        var enc = Encode(filename);
        uint ret = ((Op_encrypt_set_file_name)FFIFunction(LibSymID.op_encrypt_set_file_name))(op, enc.P);
        FreeEncoded(enc);
        return ret;
    }

    //F(op_: cd, mtime: int) -> int
    public uint rnp_op_encrypt_set_file_mtime(IntPtr op, uint mtime) {
        return ((Op_encrypt_set_file_mtime)FFIFunction(LibSymID.op_encrypt_set_file_mtime))(op, mtime);
    }

    //F(op_: cd) -> int
    public uint rnp_op_encrypt_execute(IntPtr op) {
        return ((Op_encrypt_execute)FFIFunction(LibSymID.op_encrypt_execute))(op);
    }

    //F(op_: cd) -> int
    public uint rnp_op_encrypt_destroy(IntPtr op) {
        return ((Op_encrypt_destroy)FFIFunction(LibSymID.op_encrypt_destroy))(op);
    }

    //F(ffi: cd, input_: cd, output: cd) -> int
    public uint rnp_decrypt(IntPtr ffi, IntPtr input, IntPtr output) {
        return ((Decrypt)FFIFunction(LibSymID.decrypt))(ffi, input, output);
    }

    //F(handle: cd, buf: [cd], buf_len: [int]) -> int
    public uint rnp_get_public_key_data(IntPtr handle, out RopHandle buf, out uint buf_len) {
        IntPtr cbuf = IntPtr.Zero, cbuf_len = IntPtr.Zero;
        uint ret = ((Get_public_key_data)FFIFunction(LibSymID.get_public_key_data))(handle, ref cbuf, ref cbuf_len);
        buf = new RopHandle(cbuf);
        buf_len = (uint)cbuf_len.ToInt32();
        return ret;
    }

    //F(handle: cd, buf: [cd], buf_len: [int]) -> int
    public uint rnp_get_secret_key_data(IntPtr handle, out RopHandle buf, out uint buf_len) {
        IntPtr cbuf = IntPtr.Zero, cbuf_len = IntPtr.Zero;
        uint ret = ((Get_secret_key_data)FFIFunction(LibSymID.get_secret_key_data))(handle, ref cbuf, ref cbuf_len);
        buf = new RopHandle(cbuf);
        buf_len = (uint)cbuf_len.ToInt32();
        return ret;
    }

    //F(handle: cd, flags: int, result: [cd]) -> int
    public uint rnp_key_to_json(IntPtr handle, uint flags, out RopHandle result) {
        IntPtr cresult = IntPtr.Zero;
        uint ret = ((Key_to_json)FFIFunction(LibSymID.key_to_json))(handle, flags, ref cresult);
        result = new RopHandle(cresult, true);
        return ret;
    }

    //F(ffi: cd, it_: [cd], identifier_type: str) -> int
    public uint rnp_identifier_iterator_create(IntPtr ffi, out RopHandle it, object identifier_type) {
        IntPtr cit = IntPtr.Zero;
        var enc = Encode(identifier_type);
        uint ret = ((Identifier_iterator_create)FFIFunction(LibSymID.identifier_iterator_create))(ffi, ref cit, enc.P);
        FreeEncoded(enc);
        it = new RopHandle(cit);
        return ret;
    }

    //F(it_: cd, identifier: [cd]) -> int
    public uint rnp_identifier_iterator_next(IntPtr it, out RopHandle identifier) {
        IntPtr cid = IntPtr.Zero;
        uint ret = ((Identifier_iterator_next)FFIFunction(LibSymID.identifier_iterator_next))(it, ref cid);
        identifier = new RopHandle(cid);
        return ret;
    }

    //F(it_: cd) -> int
    public uint rnp_identifier_iterator_destroy(IntPtr it) {
        return ((Identifier_iterator_destroy)FFIFunction(LibSymID.identifier_iterator_destroy))(it);
    }

    //F(input: cd, output: [cd]) -> int
    public uint rnp_output_pipe(IntPtr input, IntPtr output) {
        return ((Output_pipe)FFIFunction(LibSymID.output_pipe))(input, output);
    }
    
    //F(output: cd, llen: int) -> int
    public uint rnp_output_armor_set_line_length(IntPtr output, uint llen) {
        return ((Output_armor_set_line_length)FFIFunction(LibSymID.output_armor_set_line_length))(output, llen);
    }
    
    private void ClearCallbacks(RopHandle hnd) {
        RopCB[] cbs = null;
        if(h2cb.TryGetValue(hnd, out cbs) && cbs != null) {
            h2cb.Remove(hnd);
            foreach(RopCB cb in cbs)
                if(cb != null)
                    cb.nhnd.Free();
        }
    }

    internal static (IntPtr P, int Len, IntPtr) Encode(object data, int len = -1) {
        if(data == null)
            return (IntPtr.Zero, 0, IntPtr.Zero);
        if(data is RopHandle hdata)
            return (hdata, len, IntPtr.Zero);
        if(data is IntPtr pdata)
            return (pdata, len, IntPtr.Zero);
        if(data is byte[] bdata) {
            int plen = !(len<0)? len : bdata.Length;
            pdata = Marshal.AllocCoTaskMem(plen+1);
            Marshal.Copy(bdata, 0, pdata, plen);
            Marshal.WriteByte(pdata, plen, 0);
            return (pdata, plen, pdata);
        }
        string sdata = (string)data;
        int elen = (!(len<0)? len : sdata.Length);
        string edata = (elen<sdata.Length? sdata.Substring(0, elen) : sdata);
        pdata = Marshal.StringToCoTaskMemUTF8(edata);
        return (pdata, edata.Length, pdata);
    }

    internal static int FreeEncoded((IntPtr, int, IntPtr) data) {
        int count = 0;
        if(data.Item3 != IntPtr.Zero) {
            Marshal.FreeCoTaskMem(data.Item3);
            count++;
        }
        return count;
    }

    internal static int FreeEncoded((IntPtr, int, IntPtr)[] data) {
        int count = 0;
        foreach(var dset in data) {
            if(dset.Item3 != IntPtr.Zero) {
                Marshal.FreeCoTaskMem(dset.Item3);
                count++;
            }
        }
        return count;
    }    

    private IntPtr lib = IntPtr.Zero;
    private static SortedDictionary<LibSymID, Delegate> libSymbols = new SortedDictionary<LibSymID, Delegate>();
    private SortedDictionary<RopHandle, RopHandle> retainsI;
    private SortedDictionary<RopHandle, RopCB[]> h2cb;
}

/**
* version 0.3.1
* since   0.3.1
*/
sealed class RopCB {
    internal enum Type { PASS, KEY, INPUT, OUTPUT }

    internal Type type;
    internal RopHandle hnd;
    internal GCHandle nhnd;
    internal object ctx;
    internal object lstner1;
    
    internal RopCB(Type type, RopHandle hnd, object ctx, object lstner1) {
        this.type = type;
        this.hnd = hnd;
        this.ctx = ctx;
        this.lstner1 = lstner1;
    }
    
    internal void KeyCB(RopHandle ffi, RopHandle identifier_type, RopHandle identifier, bool secret) {
        if(ffi.CompareTo(hnd) == 0 && lstner1 != null && typeof(RopKeyCallBack).IsInstanceOfType(lstner1))
            ((RopKeyCallBack)lstner1).KeyCallBack(hnd, ctx, identifier_type, identifier, secret);
    }

    internal bool PassCB(RopHandle ffi, RopHandle key, RopHandle pgp_context, RopHandle buf, int buf_len) {
        if(ffi.CompareTo(hnd) == 0 && lstner1 != null && typeof(RopPassCallBack).IsInstanceOfType(lstner1)) {
            RopPassCallBack.Ret cbRet = ((RopPassCallBack)lstner1).PassCallBack(hnd, ctx, key, pgp_context, buf, buf_len);
            if(cbRet.outBuf != null)
                buf.WriteString(cbRet.outBuf, buf_len);
            return cbRet.ret;
        }
        return false;
    }
    
    internal long InReadCB(RopHandle buf, long len) {
        if(lstner1 != null &&  typeof(RopInputCallBack).IsInstanceOfType(lstner1)) {
            RopInputCallBack.Ret ret = ((RopInputCallBack)lstner1).InputReadCallBack(ctx, len);
            if(ret.ret)
                return buf.WriteBytes(ret.inBuf, Math.Min(ret.inLen, len));
        }
        return -1;
    }

    internal void InCloseCB() {
        if(lstner1 != null && typeof(RopInputCallBack).IsInstanceOfType(lstner1))
            ((RopInputCallBack)lstner1).InputCloseCallBack(ctx);
    }

    internal bool OutWriteCB(RopHandle buf, long len) {
        if(lstner1 != null && typeof(RopOutputCallBack).IsInstanceOfType(lstner1))
            return ((RopOutputCallBack)lstner1).OutputWriteCallBack(ctx, buf, len);
        return false;
    }

    internal void OutCloseCB(bool discard) {
        if(lstner1 != null && typeof(RopOutputCallBack).IsInstanceOfType(lstner1))
            ((RopOutputCallBack)lstner1).OutputCloseCallBack(ctx);
    }
}

}
