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
* version 0.14.0
* since   0.3.1
*/
public class RopInput : RopObject, RopInputCallBack {
    internal RopInput(RopBind own, RopHandle iid) {
        if(iid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.iid = iid;
        this.inputCB = null;
    }

    internal RopInput(RopBind own, InputCallBack inputCB) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.iid = null;
        this.inputCB = inputCB;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(iid != null) {
            ret = (int)lib.rnp_input_destroy(iid);
            iid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return iid;
    }

    internal void Attach(RopHandle iid) {
        if(iid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.iid = iid;
    }
    
    public RopInputCallBack.Ret InputReadCallBack(object ctx, long len) {
        if(inputCB != null) {
            byte[] data = inputCB.ReadCallBack(ctx, len);
            if(data != null)
                return new RopInputCallBack.Ret(data, data.Length);
        }
        return new RopInputCallBack.Ret(null, 0);
    }

    public void InputCloseCallBack(object ctx) {
        if(inputCB != null)
            inputCB.RCloseCallBack(ctx);
    }

    // API

    public RopData dump_packets_to_json(bool mpi = false, bool raw = false, bool grip = false) {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = (int)lib.rnp_dump_packets_to_json(iid, (uint)flags, out RopHandle hnd);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), 0);
            bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData dump_packets_to_json_mpi() {
        return dump_packets_to_json(true, false, false);
    }
    public RopData dump_packets_to_json_raw() {
        return dump_packets_to_json(false, true, false);
    }
    public RopData dump_packets_to_json_grip() {
        return dump_packets_to_json(false, false, true);
    }
    public void dump_packets_to_output(RopOutput output, bool mpi = false, bool raw = false, bool grip = false) {
        int flags = (mpi? ROPD.RNP_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_DUMP_GRIP : 0);
        int ret = (int)lib.rnp_dump_packets_to_output(iid, output!=null? output.getHandle() : RopHandle.Null, (uint)flags);
        Util.Return(ret);
    }
    public void dump_packets_to_output_mpi(RopOutput output) {
        dump_packets_to_output(output, true, false, false);
    }
    public void dump_packets_to_output_raw(RopOutput output) {
        dump_packets_to_output(output, false, true, false);
    }
    public void dump_packets_to_output_grip(RopOutput output) {
        dump_packets_to_output(output, false, false, true);
    }
    public void enarmor(RopOutput output, string type) {
        int ret = (int)lib.rnp_enarmor(iid, output!=null? output.getHandle() : RopHandle.Null, type);
        Util.Return(ret);
    }
    public void dearmor(RopOutput output) {
        int ret = (int)lib.rnp_dearmor(iid, output!=null? output.getHandle() : RopHandle.Null);
        Util.Return(ret);
    }
    public string guess_contents() {
        int ret = (int)lib.rnp_guess_contents(iid, out RopHandle hnd);
        return Util.GetRopString(lib, ret, hnd);
    }
    public void output_pipe(RopOutput output) {
        int ret = (int)lib.rnp_output_pipe(iid, output!=null? output.getHandle() : RopHandle.Null);
        Util.Return(ret);
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle iid;
    private InputCallBack inputCB;
}
    
/** 
* version 0.14.0
* since   0.3.1
*/
public class RopOutput : RopObject, RopOutputCallBack {
    internal RopOutput(RopBind own, RopHandle oid) {
        if(oid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.oid = oid;
        this.outputCB = null;
    }

    internal RopOutput(RopBind own, OutputCallBack outputCB) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.oid = null;
        this.outputCB = outputCB;
    }

    internal override int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(oid != null) {
            ret = (int)lib.rnp_output_finish(oid);
            int ret2 = (int)lib.rnp_output_destroy(oid);
            ret = (ret==ROPE.RNP_SUCCESS && ret2!=ROPE.RNP_SUCCESS? ret2 : ret);
            oid = null;
        }
        return ret;
    }

    public RopHandle getHandle() {
        return oid;
    }

    internal void Attach(RopHandle oid) {
        if(oid.IsNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.oid = oid;
    }

    public bool OutputWriteCallBack(object ctx, RopHandle buf, long len) {
        if(outputCB != null && buf != null && len > 0) {
            if(own.TryGetTarget(out RopBind bind))
                return outputCB.WriteCallBack(ctx, new RopData(bind, buf, len));
            throw new RopError(RopBind.ROP_ERROR_INTERNAL);
        }
        return false;
    }
    public void OutputCloseCallBack(object ctx) {
        if(outputCB != null)
            outputCB.WCloseCallBack(ctx);
    }

    // API

    public RopOutput output_to_armor(string type, int tag = 0) {
        int ret = (int)lib.rnp_output_to_armor(oid, out RopHandle hnd, type);
        if(own.TryGetTarget(out RopBind bind)) {
            RopOutput arm = new RopOutput(bind, Util.PopHandle(lib, hnd, ret));
            bind.PutObj(arm, tag);
            return arm;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public RopData memory_get_buf(bool doCopy) {
        int ret = (int)lib.rnp_output_memory_get_buf(oid, out RopHandle hnd, out long ln, doCopy);
        long len = Util.PopLong(lib, ln, ret);
        if(own.TryGetTarget(out RopBind bind)) {
            RopData data = new RopData(bind, Util.PopHandle(lib, hnd, ret), len);
            if(doCopy)
                bind.PutObj(data, 0);
            return data;
        }
        throw new RopError(RopBind.ROP_ERROR_INTERNAL);
    }
    public long write(RopData data) {
        int ret = (int)lib.rnp_output_write(oid, data.getDataObj(), data.getDataLen(), out long wr);
        return Util.PopLong(lib, wr, ret);
    }
    public void armor_set_line_length(int llen) {
        int ret = (int)lib.rnp_output_armor_set_line_length(oid, (uint)llen);
        Util.Return(ret);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle oid;
    private OutputCallBack outputCB;
}

}
