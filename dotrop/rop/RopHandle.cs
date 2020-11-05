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
using System.Runtime.InteropServices;


namespace tech.janky.dotrop.rop {

/**
* version 0.3.1
* since   0.3.1
*/
public sealed class RopHandle : IComparable<RopHandle> {
    private enum PtrType {
        PtrTypeRaw,
        PtrTypeString
    }
    
    public RopHandle(IntPtr ptr, bool p2String = false) {
        this.ptr = ptr;
        this.type = (p2String? PtrType.PtrTypeString : PtrType.PtrTypeRaw);
        this.source = IntPtr.Zero;
    }

    public static RopHandle Cast2Str(RopHandle hnd) {
        return hnd.type!=PtrType.PtrTypeString? new RopHandle(hnd.ptr, true) : hnd;
    }

    public static string Str(RopHandle hnd) {
        return hnd!=null? Cast2Str(hnd).ToString() : null;
    }

    public bool IsNull() {
        return ptr.Equals(IntPtr.Zero);
    }

    public int AsciiZLen() {
        int len = 0;
        if(!ptr.Equals(IntPtr.Zero)) unsafe {
            byte *pt = (byte*)ptr.ToPointer();
            while(*pt++ != 0) len++;
        }
        return len;
    }

    public override string ToString() {
        if(type == PtrType.PtrTypeString)
            return !IsNull()? Marshal.PtrToStringUTF8(ptr) : null;
        return "0x" + ptr.ToString("X");
    }

    public SecureString ToSecureString() {
        SecureString str = null;
        if(!ptr.Equals(IntPtr.Zero) && type == PtrType.PtrTypeString) unsafe {
            char *sptr = (char*)ptr.ToPointer();
            str = new SecureString(sptr, AsciiZLen());
        }
        return str;
    }

    public byte[] ToBytes(long len) {
        if(len == 0)
            len = AsciiZLen();
        byte[] output = null;
        if(!IsNull() && len > 0) {
            output = new byte[len];
            Marshal.Copy(ptr, output, 0, (int)len);
        }
        return output;
    }

    public int WriteString(object buf, int maxLen) {
        int len = 0;
        var enc = RopLib.Encode(buf);
        if(!enc.P.Equals(IntPtr.Zero)) unsafe {
            byte *src = (byte*)enc.P.ToPointer();
            byte *dst = (byte*)ptr.ToPointer();
            while(*src != 0 && len < maxLen-1)
                dst[len++] = *src++;
            dst[len] = 0;
        }
        RopLib.FreeEncoded(enc);
        return len;
    }

    public long WriteBytes(byte[] buf, long len) {
        Marshal.Copy(buf, 0, ptr, (int)len);
        return len;
    }

    public void ClearMemory(long len) {
        if(!ptr.Equals(IntPtr.Zero)) unsafe {
            byte *pt = (byte*)ptr.ToPointer();
            if(len >= 0)
                while(len-- > 0) *pt++ = 0;
            else
                while(*pt != 0) *pt++ = 0;
        }
    }

    public void ClearMemory() { 
        ClearMemory(-1); 
    }

    public int CompareTo(RopHandle obj) { long i1 = this.ptr.ToInt64(), i2 = obj.ptr.ToInt64(); return i1<i2? -1 : (i1>i2? 1 : 0); }
    
    public IntPtr Source { get { return source; } set { if(source != IntPtr.Zero) Marshal.FreeCoTaskMem(source); source = value; } }

    public static implicit operator IntPtr(RopHandle hnd) => (hnd!=null? hnd.ptr : IntPtr.Zero);

    public static RopHandle Null { get{ return hnull; } } 
    private static RopHandle hnull = new RopHandle(IntPtr.Zero);

    public IntPtr ptr { get; }
    private PtrType type;
    internal IntPtr source;
}
    
}
