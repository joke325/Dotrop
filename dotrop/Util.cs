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
public sealed class Util {
    public static string GetRopString(RopLib rop, int ret, RopHandle ropStr, bool freeBuf = true) {
        string sval = RopHandle.Str(ropStr);
        if(freeBuf)
            rop.rnp_buffer_destroy(ropStr);
        if(ret != ROPE.RNP_SUCCESS)
            throw new RopError(ret);
        return sval;
    }

    public static string[] GetRopStrings(RopLib rop, int ret, RopHandle[] ropStrs, bool freeBuf = true) {
        string[] svals = new string[ropStrs.Length];
        for(int idx = 0; idx < ropStrs.Length; idx++) {
            svals[idx] = RopHandle.Str(ropStrs[idx]);
            if(freeBuf)
                rop.rnp_buffer_destroy(ropStrs[idx]);
        }
        if(ret != ROPE.RNP_SUCCESS)
            throw new RopError(ret);
        return svals;
    }

    public static RopHandle PopHandle(RopLib rop, RopHandle val, int err) {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        return val;
    }

    public static int PopInt(RopLib rop, int val, int err) {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        return val;
    }

    public static long PopLong(RopLib rop, long val, int err) {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        return val;
    }

    public static bool PopBool(RopLib rop, bool val, int err) {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        return val;
    }

    public static void Return(int err) {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
    }	

    public static long Datetime2TS(DateTime dtime) {
        return dtime.Ticks!=0? new DateTimeOffset(dtime).ToUnixTimeSeconds() : 0L;
    }

    public static long TimeDelta2Sec(TimeSpan tdtime) {
        return tdtime.Ticks!=0? Convert.ToInt64(tdtime.TotalSeconds) : 0L;
    }
}

}
