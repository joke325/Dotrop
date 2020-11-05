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
using tech.janky.dotrop.rop;


namespace tech.janky.dotrop {

/** 
* <summary>Encapsulates String, byte[], RopHandle data</summary>
* version 0.3.1
* since   0.3.1
*/
public class RopData : RopObject {
    internal RopData(RopBind own, RopHandle hnd, long dataLen) {
        this.lib = own.getLib();
        this.hnd = hnd;
        this.dataLen = dataLen;
        this.sdata = null;
        this.bdata = null;
    }
    
    /** 
    * Constructor
    */
    public RopData(string data) {
        this.lib = null;
        this.hnd = null;
        this.dataLen = 0;
        this.sdata = data;
        this.bdata = null;
    }

    /** 
    * Constructor
    */
    public RopData(byte[] data) {
        this.lib = null;
        this.hnd = null;
        this.dataLen = 0;
        this.sdata = null;
        this.bdata = data;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(hnd != null) {
            lib.rnp_buffer_destroy(hnd);
            hnd = null;
            dataLen = 0;
        }
        return ret;
    }

    /**
    * @return string data
    */
    public string getString() {
        if(sdata != null)
            return sdata;
        if(hnd != null && !hnd.IsNull()) {
            string str = RopHandle.Str(hnd);
            return str!=null&&0<dataLen&&dataLen<str.Length? str.Substring(0, (int)dataLen) : str;
        }
        return null;
    }

    /**
    * @return byte[] data
    */
    public byte[] getBytes(long len) {
        if(bdata != null) {
            byte[] ret = (!(0<len&&len<bdata.Length)? bdata : new byte[len]);
            if(ret != bdata)
                Array.Copy(bdata, 0, ret, 0, ret.Length);
            return ret;
        }
        if(hnd != null && !hnd.IsNull())
            return hnd.ToBytes(len==0||(0<dataLen&&dataLen<len)? dataLen : len);
        return null;
    }

    /**
    * @return byte[] data
    */
    public byte[] getBytes() {
        return getBytes(0);
    }

    /**
    * @return RopHandle data
    */
    public RopHandle getHandle() {
        return hnd;
    }

    /**
    * @return length of data
    */
    public long getLength() {
        return getDataLen();
    }

    public bool isNull() {
        if(hnd != null)
            return hnd.IsNull();
        return sdata == null && bdata == null;
    }
    
    internal object getDataObj() {
        if(sdata != null)
            return sdata;
        if(bdata != null)
            return bdata;
        return hnd;
    }

    internal long getDataLen() {
        if(sdata != null)
            return sdata.Length;
        if(bdata != null)
            return bdata.Length;
        return dataLen;
    }

    private RopLib lib;
    private RopHandle hnd;
    private long dataLen;
    private string sdata;
    private byte[] bdata;
}

}
