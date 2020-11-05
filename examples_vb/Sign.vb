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

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/sign.c

Public Class Sign
    Implements SessionPassCallBack

    Public Shared key_ids() As String = {"Dummy", "Dummy"}
    Public Shared key_fprints() As String = {"Dummy", "Dummy"}

    ' an example pass provider
    Public Function PassCallBack(ses As RopSession, ctx As Object, key As RopKey, pgpCtx As String, bufLen As Integer) As SessionPassCallBack.Ret Implements SessionPassCallBack.PassCallBack
        return New SessionPassCallBack.Ret(True, "password")
    End Function

    Private Sub sign(rop As RopBind)
        Dim message As String = "ROP signing sample message"

        Dim alt As Integer = rop.tagging()
        Try
            ' initialize
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            Dim keyfile As RopInput = Nothing
            Dim err_desc As String = Nothing
            Try
                ' load secret keyring, as it is required for signing. However, you may need
                ' to load public keyring as well to validate key's signatures.
                err_desc = "Failed to open secring.pgp. Did you run Generate.java sample?"
                keyfile = rop.create_input("secring.pgp")

                ' we may use public=True and secret=True as well
                err_desc = "Failed to read secring.pgp"
                ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine(err_desc)
                Throw ex
            Finally
                rop.drop(keyfile)
            End Try

            ' set the password provider - we'll need password to unlock secret keys
            ses.set_pass_provider(Me, Nothing)

            ' create file input and memory output objects for the encrypted message
            ' and decrypted message
            Dim sign As RopOpSign = Nothing
            Try
                err_desc = "Failed to create input object"
                Dim input As RopInput = rop.create_input(new RopData(message), False)

                err_desc = "Failed to create output object"
                Dim output As RopOutput = rop.create_output("signed.asc")

                ' initialize and configure sign operation, use op_sign_create(cleartext/detached)
                ' for cleartext or detached signature
                err_desc = "Failed to create sign operation"
                sign = ses.op_sign_create(input, output)
            Catch ex As RopError
                Console.WriteLine(err_desc)
                Throw ex
            End Try

            ' armor, file name, compression
            sign.set_armor(True)
            sign.set_file_name("message.txt")
            sign.set_file_mtime(DateTime.Now)
            sign.set_compression("ZIP", 6)
            ' signatures creation time - by default will be set to the current time as well
            sign.set_creation_time(DateTime.Now)
            ' signatures expiration time - by default will be 0, i.e. never expire
            sign.set_expiration(TimeSpan.FromDays(365))
            ' set hash algorithm - should be compatible for all signatures
            sign.set_hash(RopBind.ALG_HASH_SHA256)

            Try
                ' now add signatures. First locate the signing key, then add and setup signature
                ' RSA signature
                err_desc = "Failed to locate signing key rsa@key."
                Dim key As RopKey = ses.locate_key("userid", "rsa@key")
                examples_vb.Sign.key_ids(0) = key.keyid()
                examples_vb.Sign.key_fprints(0) = key.fprint()

                err_desc = "Failed to add signature for key rsa@key."
                sign.add_signature(key)

                ' EdDSA signature
                err_desc = "Failed to locate signing key 25519@key."
                key = ses.locate_key("userid", "25519@key")
                examples_vb.Sign.key_ids(1) = key.keyid()
                examples_vb.Sign.key_fprints(1) = key.fprint()

                err_desc = "Failed to add signature for key 25519@key."
                sign.add_signature(key)

                ' finally do signing
                err_desc = "Failed to add signature for key 25519@key."
                sign.execute()

                Console.WriteLine("Signing succeeded. See file signed.asc.")
            Catch ex As RopError
                Console.WriteLine(err_desc)
                Throw ex
            End Try
        Finally
            rop.drop_from(alt)
        End Try
    End Sub

    Public Sub execute()
        Dim rop As RopBind = New RopBind()
        Try
            sign(rop)
        Finally
            rop.Close()
        End Try
    End Sub

    Public Shared Sub Main(args As String())
        Dim sign As Sign = New Sign()
        sign.execute()
    End Sub
End Class

End Namespace
