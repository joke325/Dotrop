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
Imports tech.janky.dotrop


Namespace tech.janky.dotrop.examples_vb

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/verify.c

Public Class Verify
    Implements SessionKeyCallBack

    ' an example key provider
    Public Sub KeyCallBack(ses As RopSession, ctx As Object, identifier_type As String, identifier As String, secret As Boolean) Implements SessionKeyCallBack.KeyCallBack
        If identifier_type.CompareTo("keyid") = 0 Then
            Dim filename As String = String.Format("key-{0}-{1}.asc", identifier, If(secret, "sec", "pub"))
            Dim err_desc As String = Nothing
            Try
                Dim rop As WeakReference(Of RopBind) = ses.getBind()
                err_desc = String.Format("failed to open key file {0}", filename)
                Dim bind As RopBind = Nothing
                Dim input As RopInput = If(rop.TryGetTarget(bind), bind.create_input(filename), Nothing)

                err_desc = String.Format("failed to load key from file {0}", filename)
                ses.load_keys(RopBind.KEYSTORE_GPG, input, True, True)
            Catch ex As RopError
                Console.WriteLine(err_desc)
            End Try
        End If
    End Sub

    Private Sub verify(rop As RopBind)
        Dim alt As Integer = rop.tagging()
        Try
            ' initialize
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            ' we do not load any keys here since we'll use key provider
            ses.set_key_provider(Me, Nothing)

            Dim err_desc As String = Nothing
            Dim output As RopOutput = Nothing
            Try
                ' create file input and memory output objects for the signed message
                ' and verified message
                err_desc = "Failed to open file 'signed.asc'. Did you run the sign example?"
                Dim input As RopInput = rop.create_input("signed.asc")

                err_desc = "Failed to create output object"
                output = rop.create_output(0)

                err_desc = "Failed to create verification context"
                Dim verify As RopOpVerify = ses.op_verify_create(input, output)

                err_desc = "Failed to execute verification operation"
                verify.execute()

                ' now check signatures and get some info about them
                err_desc = "Failed to get signature count"
                Dim sigcount As Integer = verify.signature_count()

                for idx As Integer = 0 To sigcount-1
                    rop.tagging()

                    err_desc = String.Format("Failed to get signature {0}", idx)
                    Dim sig As RopVeriSignature = verify.get_signature_at(idx)

                    err_desc = String.Format("failed to get signature's {0} key", idx)
                    Dim key As RopKey = sig.get_key()

                    err_desc = String.Format("failed to get key id {0}", idx)

                    Console.WriteLine(String.Format("Status for signature from key {0} : {1}", key.keyid(), sig.status()))
                    rop.drop()
                Next
            Catch ex As RopError
                Console.WriteLine(err_desc)
                Throw ex
            End Try

            ' get the verified message from the output structure
            Dim buf As RopData = output.memory_get_buf(False)
            Console.WriteLine(String.Format("Verified message: {0}", buf.getString()))
        Finally
            rop.drop_from(alt)
        End Try
    End Sub
    
    Public Sub execute()
        Dim rop As RopBind = New RopBind()
        Try
            verify(rop)
        Finally
            rop.Close()
        End Try
    End Sub

    Public Shared Sub Main(args As String())
        Dim ver As Verify = New Verify()
        ver.execute()
    End Sub
End Class

End Namespace
