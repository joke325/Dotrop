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

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/decrypt.c

Public Class Decrypt
    Implements SessionPassCallBack

    Public Shared message As String = "Dummy"

    Public Function PassCallBack(ses As RopSession, ctx As Object, key As RopKey, pgpCtx As String, bufLen As Integer) As SessionPassCallBack.Ret Implements SessionPassCallBack.PassCallBack
        If pgpCtx.CompareTo("decrypt (symmetric)") = 0 Then
            return New SessionPassCallBack.Ret(True, "encpassword")
        End If
        If pgpCtx.CompareTo("decrypt") = 0 Then
            return New SessionPassCallBack.Ret(True, "password")
        End If
        return New SessionPassCallBack.Ret(False, Nothing)
    End Function

    Private Sub decrypt(rop As RopBind, usekeys As Boolean)
        Dim alt As Integer = rop.tagging()
        Try
            ' initialize FFI object
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            ' check whether we want to use key or password for decryption
            If usekeys
                Dim keyfile As RopInput = Nothing
                Try
                    ' load secret keyring, as it is required for public-key decryption. However, you may
                    ' need to load public keyring as well to validate key's signatures.
                    keyfile = rop.create_input("secring.pgp")
                    ' we may use secret=True and public=True as well
                    ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile)
                Catch ex As RopError
                    Console.WriteLine("Failed to read secring")
                    Throw ex
                Finally
                    rop.drop(keyfile)
                End Try
            End If

            ' set the password provider
            ses.set_pass_provider(Me, Nothing)
            Dim buf As String = Nothing
            Try
                ' create file input and memory output objects for the encrypted message and decrypted
                ' message
                Dim input As RopInput = rop.create_input("encrypted.asc")
                Dim output As RopOutput = rop.create_output(0)
                ses.decrypt(input, output)
                ' get the decrypted message from the output structure
                buf = output.memory_get_buf(false).getString()
            Catch ex As RopError
                Console.WriteLine("Public-key decryption failed")
                Throw ex
            End Try

            Console.WriteLine(String.Format("Decrypted message ({0}):" & Environment.NewLine & "{1}" & Environment.NewLine, If(usekeys, "with key", "with password"), buf))
            examples_vb.Decrypt.message = buf
        Finally
            rop.drop_from(alt)
        End Try
    End Sub
    
    Public Sub execute()
        Dim rop As RopBind = new RopBind()
        Try
            decrypt(rop, True)
            decrypt(rop, False)
        Finally
            rop.Close()
        End Try
    End Sub

    Shared Sub Main(args As String())
        Dim dec As Decrypt = new Decrypt()
        dec.execute()
    End Sub
End Class

End Namespace
