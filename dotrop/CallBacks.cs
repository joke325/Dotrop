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

namespace tech.janky.dotrop {

/**
* version 0.3.1
* since   0.3.1
*/
public interface SessionKeyCallBack {
    public void KeyCallBack(RopSession ses, object ctx, string identifier_type, string identifier, bool secret);
}

/**
* version 0.3.1
* since   0.3.1
*/
public interface SessionPassCallBack {
    public struct Ret {
        public Ret(bool ret, string outBuf) { this.ret = ret; this.outBuf = outBuf; }
        public bool ret;
        public string outBuf;
    }
    public Ret PassCallBack(RopSession ses, object ctx, RopKey key, string pgpCtx, int bufLen);
}

/**
* version 0.3.1
* since   0.3.1
*/
public interface InputCallBack {
    public byte[] ReadCallBack(object ctx, long maxLen);
    public void RCloseCallBack(object ctx);
}

/**
* version 0.3.1
* since   0.3.1
*/
public interface OutputCallBack {
    public bool WriteCallBack(object ctx, RopData buf);
    public void WCloseCallBack(object ctx);
}

}
