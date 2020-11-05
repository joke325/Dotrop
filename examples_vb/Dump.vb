' Copyright (c) 2020 Janky <box@janky.tech>
' All right reserved.
'
' Redistribution and use in source and binary forms, with or without modification,
' are permitted provided that the following conditions are met:
'
' 1. Redistributions of source code must retain the above copyright notice,
'    this list of conditions and the following disclaimer.
'
' 2. Redistributions in binary form must reproduce the above copyright notice,
'    this list of conditions and the following disclaimer in the documentation
'    and/or other materials provided with the distribution.
'
' THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
' THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
' ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
' BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
' OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
' OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
' INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
' IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
' ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
' THE POSSIBILITY OF SUCH DAMAGE.
'
Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports tech.janky.dotrop


Namespace tech.janky.dotrop.examples_vb

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/dump.c

Public Class Dump
    Implements InputCallBack, OutputCallBack
    ' stdin reader
    Public Function ReadCallBack(ctx As Object, maxLen As Long) As Byte() Implements InputCallBack.ReadCallBack
        Dim buf(CInt(maxLen)) As Byte
        Dim read As Integer = -1
        Dim ins As Stream = Nothing
        Try
            ins = Console.OpenStandardInput()
            read = ins.Read(buf, 0, buf.Length)
        Catch ex As IOException
        Finally
            If ins IsNot Nothing Then ins.Dispose()
        End Try
        return If(read>=0, buf.Take(read).ToArray(), Nothing)
    End Function
    Public Sub RCloseCallBack(ctx As Object) Implements InputCallBack.RCloseCallBack
    End Sub
    
    ' stdout writer
    Public Function WriteCallBack(ctx As Object, buf As RopData) As Boolean Implements OutputCallBack.WriteCallBack
        Console.Write(buf.getString())
        return True
    End Function
    public Sub WCloseCallBack(ctx As Object) Implements OutputCallBack.WCloseCallBack
        Console.WriteLine("")
    End Sub

    Private Shared LF As String = Environment.NewLine

    Private Sub print_usage(program_name As String)
        Console.Error.Write(String.Format(
            "Program dumps PGP packets. " & LF & LF & "Usage:" & LF &
            vbTab & "%s [-d|-h] [input.pgp]" & LF &
            vbTab & "  -d : indicates whether to print packet content. Data is represented as hex" & LF &
            vbTab & "  -m : dump mpi values" & LF &
            vbTab & "  -g : dump key fingerprints and grips" & LF &
            vbTab & "  -j : JSON output" & LF &
            vbTab & "  -h : prints help and exists" & LF &
            Path.GetFileName(program_name)))
    End Sub

    Public Sub execute(argv As String(), json_out As String())
        Dim input_file AS String = Nothing
        Dim raw As Boolean = False
        Dim mpi As Boolean = False
        Dim grip As Boolean = False
        Dim json As Boolean = False
        Dim help As Boolean = (argv.Length < 2)

        ' Parse command line options:
        '    -i input_file [mandatory]: specifies name of the file with PGP packets
        '    -d : indicates wether to dump whole packet content
        '    -m : dump mpi contents
        '    -g : dump key grips and fingerprints
        '    -j : JSON output
        '    -h : prints help and exists
        Dim opts As List(Of String) = New List(Of String)(), args As List(Of String) = New List(Of String)()
        For idx As Integer = 1 To argv.Length-1
            If argv(idx).Length >= 2 And argv(idx)(0) = "-"c And "dmgjh".IndexOf(argv(idx)(1)) >= 0 Then
                opts.Add(argv(idx))
            else
                args.Add(argv(idx))
            End If
        Next
        For Each opt As String In opts
            If opt.CompareTo("-d") = 0 Then
                raw = True
            Else If opt.CompareTo("-m") = 0 Then
                mpi = True
            Else If opt.CompareTo("-g") = 0 Then
                grip = True
            Else If opt.CompareTo("-j") = 0 Then
                json = True
            Else If opt.Length > 0 Then
                help = True
            End If
        Next
        If Not help Then
            If args.Count > 0 Then
                input_file = args(0)
            End If

            Dim rop As RopBind = New RopBind()
            Try
                Dim input As RopInput = Nothing
                Dim output As RopOutput = Nothing
                Try
                    If input_file IsNot Nothing Then
                        input = rop.create_input(input_file)
                    else
                        input = rop.create_input(Me, Nothing)
                    End If
                Catch err As RopError
                    Console.WriteLine(String.Format("Failed to open source: error {0}", err.getErrCode()))
                    Throw err
                End Try

                If Not json Then
                    Try
                        output = rop.create_output(Me, app_ctx:=Nothing)
                    Catch err As RopError
                        Console.WriteLine(String.Format("Failed to open stdout: error {0}", err.getErrCode()))
                        Throw err
                    End Try
                    input.dump_packets_to_output(output, mpi, raw, grip)
                Else
                    Dim jsn As String = input.dump_packets_to_json(mpi, raw, grip).getString()
                    If json_out Is Nothing Then
                        Console.WriteLine(jsn)
                        Console.WriteLine("")
                    Else
                        json_out(0) = jsn
                    End If
                End If
            Catch err As RopError
                ' Inform in case of error occured during parsing
                Console.WriteLine(String.Format("Operation failed [error code: {0}]", err.getErrCode()))
                Throw err
            Finally
                rop.Close()
            End Try
        Else
            print_usage(argv(0))
        End If
    End Sub

    Public Shared Sub Main(args As String())
        Dim dump As Dump = New Dump()
        Dim newArgs(args.Length) As String
        newArgs(0) = dump.GetType().Name
        Array.Copy(args, 0, newArgs, 1, args.Length)
        dump.execute(newArgs, Nothing)
    End Sub
End Class

End Namespace
