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

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/encrypt.c

Public Class Encrypt
    Public Const message As String = "ROP encryption sample message"

    Private Sub encrypt(rop As RopBind)
        Dim alt As Integer = rop.tagging()
        Try
            ' initialize
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            Dim keyfile As RopInput = Nothing
            Try
                ' load public keyring - we do not need secret for encryption
                keyfile = rop.create_input("pubring.pgp")
                ' we may use secret=True and public=True as well
                ses.load_keys_public(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine("Failed to read pubring")
                Throw ex
            Finally
                rop.drop(keyfile)
            End Try

            Try
                ' create memory input and file output objects for the message and encrypted message
                Dim input As RopInput = rop.create_input(new RopData(message), False)
                Dim output As RopOutput = rop.create_output("encrypted.asc")
                ' create encryption operation
                Dim encrpt As RopOpEncrypt = ses.op_encrypt_create(input, output)

                ' setup encryption parameters
                encrpt.set_armor(True)
                encrpt.set_file_name("message.txt")
                encrpt.set_file_mtime(DateTime.Now)
                encrpt.set_compression("ZIP", 6)
                encrpt.set_cipher(RopBind.ALG_SYMM_AES_256)
                encrpt.set_aead("None")

                ' locate recipient's key and add it to the operation context. While we search by userid
                ' (which is easier), you can search by keyid, fingerprint or grip.
                Dim key As RopKey = ses.locate_key("userid", "rsa@key")
                encrpt.add_recipient(key)
                ' add encryption password as well
                encrpt.add_password("encpassword", RopBind.ALG_HASH_SHA256, 0, RopBind.ALG_SYMM_AES_256)

                ' execute encryption operation
                encrpt.execute()

                Console.WriteLine("Encryption succeded. Encrypted message written to file encrypted.asc")
            Catch ex As RopError
                Console.WriteLine("Encryption failed")
                Throw ex
            End Try
        Finally
            rop.drop_from(alt)
        End Try
    End Sub

    Public Sub execute()
        Dim rop As RopBind = New RopBind()
        Try
            encrypt(rop)
        Finally
            rop.Close()
        End Try
    End Sub

    Shared Sub Main(Args As string())
        Dim enc As Encrypt = new Encrypt()
        enc.execute()
    End Sub
End Class

End Namespace
