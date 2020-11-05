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
using System.Linq;
using tech.janky.dotrop;

    
namespace tech.janky.dotrop.examples {

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/dump.c

public class Dump : InputCallBack, OutputCallBack {
    // stdin reader
    public byte[] ReadCallBack(object ctx, long maxLen) {
        byte[] buf = new byte[(int)maxLen];
        int read = -1;
        try {
            using(Stream ins = Console.OpenStandardInput()) {
                read = ins.Read(buf, 0, buf.Length);
            }
        } catch(IOException) {}
        return read>=0? buf.Take(read).ToArray() : null;
    }
    public void RCloseCallBack(object ctx) { }
    
    // stdout writer
    public bool WriteCallBack(object ctx, RopData buf) {
        Console.Write(buf.getString());
        return true;
    }
    public void WCloseCallBack(object ctx) {
        Console.WriteLine("");
    }

    private void print_usage(string program_name) {
        Console.Error.Write(String.Format(
            "Program dumps PGP packets. \n\nUsage:\n" +
            "\t%s [-d|-h] [input.pgp]\n" +
            "\t  -d : indicates whether to print packet content. Data is represented as hex\n" +
            "\t  -m : dump mpi values\n" +
            "\t  -g : dump key fingerprints and grips\n" +
            "\t  -j : JSON output\n" +
            "\t  -h : prints help and exists\n",
            Path.GetFileName(program_name)));
    }

    public void execute(string[] argv, string[] json_out) {
        string input_file = null;
        bool raw = false;
        bool mpi = false;
        bool grip = false;
        bool json = false;
        bool help = (argv.Length < 2);

        /* Parse command line options:
            -i input_file [mandatory]: specifies name of the file with PGP packets
            -d : indicates wether to dump whole packet content
            -m : dump mpi contents
            -g : dump key grips and fingerprints
            -j : JSON output
            -h : prints help and exists
        */
        List<string> opts = new List<string>(), args = new List<string>();
        for(int idx = 1; idx < argv.Length; idx++)
            if(argv[idx].Length >= 2 && argv[idx][0] == '-' && "dmgjh".IndexOf(argv[idx][1]) >= 0)
                opts.Add(argv[idx]);
            else
                args.Add(argv[idx]);
        foreach(string opt in opts) {
            if(opt.CompareTo("-d") == 0)
                raw = true;
            else if(opt.CompareTo("-m") == 0)
                mpi = true;
            else if(opt.CompareTo("-g") == 0)
                grip = true;
            else if(opt.CompareTo("-j") == 0)
                json = true;
            else if(opt.Length > 0)
                help = true;
        }
        if(!help) {
            if(args.Count > 0)
                input_file = args[0];

            RopBind rop = new RopBind();
            try {
                RopInput input = null;
                RopOutput output = null;
                try {
                    if(input_file != null)
                        input = rop.create_input(input_file);
                    else
                        input = rop.create_input(this, null);
                } catch(RopError err) {
                    Console.WriteLine(String.Format("Failed to open source: error {0}", err.getErrCode()));
                    throw err;
                }

                if(!json) {
                    try {
                        output = rop.create_output(this, null);
                    } catch(RopError err) {
                        Console.WriteLine(String.Format("Failed to open stdout: error {0}", err.getErrCode()));
                        throw err;
                    }
                    input.dump_packets_to_output(output, mpi, raw, grip);
                } else {
                    string jsn = input.dump_packets_to_json(mpi, raw, grip).getString();
                    if(json_out == null) {
                        Console.WriteLine(jsn);
                        Console.WriteLine("");
                    } else
                        json_out[0] = jsn;
                }
            } catch(RopError err) {
                // Inform in case of error occured during parsing
                Console.WriteLine(String.Format("Operation failed [error code: {0}]", err.getErrCode()));
                throw err;
            } finally {
                rop.Close();
            }
        } else {
            print_usage(argv[0]);
        }
    }

    public static void Main(string[] args) {
        Dump dump = new Dump();
        string[] newArgs = new string[args.Length+1];
        newArgs[0] = dump.GetType().Name;
        Array.Copy(args, 0, newArgs, 1, args.Length);
        dump.execute(newArgs, null);
    }
}

}
