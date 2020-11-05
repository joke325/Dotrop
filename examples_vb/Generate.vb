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

' Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/generate.c

Public Class Generate 
    Implements SessionPassCallBack
    
    ' RSA key JSON description. 31536000 = 1 year expiration, 15768000 = half year
    Public Const RSA_KEY_DESC As String =
        "{" &
            "'primary': {" &
                "'type': 'RSA'," &
                "'length': 2048," &
                "'userid': 'rsa@key'," &
                "'expiration': 31536000," &
                "'usage': ['sign']," &
                "'protection': {" &
                    "'cipher': 'AES256'," &
                    "'hash': 'SHA256'" &
                "}" &
            "}," &
            "'sub': {" &
                "'type': 'RSA'," &
                "'length': 2048," &
                "'expiration': 15768000," &
                "'usage': ['encrypt']," &
                "'protection': {" &
                    "'cipher': 'AES256'," &
                    "'hash': 'SHA256'" &
                "}" &
            "}" &
        "}"
    Public Const CURVE_25519_KEY_DESC As String = 
        "{" &
            "'primary': {" &
                "'type': 'EDDSA'," &
                "'userid': '25519@key'," &
                "'expiration': 0," &
                "'usage': ['sign']," &
                "'protection': {" &
                    "'cipher': 'AES256'," &
                    "'hash': 'SHA256'" &
                "}" &
            "}," &
            "'sub': {" &
                "'type': 'ECDH'," &
                "'curve': 'Curve25519'," &
                "'expiration': 15768000," &
                "'usage': ['encrypt']," &
                "'protection': {" &
                    "'cipher': 'AES256'," &
                    "'hash': 'SHA256'" &
                "}" &
            "}" &
        "}"

    ' basic pass provider implementation, which always return 'password' for key protection.
    ' You may ask for password via stdin, or choose password based on key properties, whatever else 
    Public Function PassCallBack(ses As RopSession, ctx As Object, key As RopKey, pgpCtx As String, bufLen As Integer) As SessionPassCallBack.Ret Implements SessionPassCallBack.PassCallBack
        If pgpCtx.CompareTo("protect") = 0 Then
            return New SessionPassCallBack.Ret(true, "password")
        End If
        return New SessionPassCallBack.Ret(false, Nothing)
    End Function

    ' This simple helper function just prints armored key, searched by userid, to stdout.
    Private Sub print_key(rop As RopBind, ses As RopSession, uid As String, secret As Boolean)
        ' you may search for the key via userid, keyid, fingerprint, grip
        Dim key As RopKey = ses.locate_key("userid", uid)
        ' create in-memory output structure to later use buffer
        Dim keydata As RopOutput = rop.create_output(0)
        Try
            If secret Then
                key.export_secret(keydata, true, true)
            Else
                key.export_public(keydata, true, true)
            End If
            ' get key's contents from the output structure
            Dim buf As RopData = keydata.memory_get_buf(false)
            Console.WriteLine(buf.getString())
        Finally
            rop.drop(keydata)
        End Try
    End Sub

    Private Sub export_key(rop As RopBind, ses As RopSession, uid As String, secret As Boolean)
        ' you may search for the key via userid, keyid, fingerprint, grip
        Dim key As RopKey = ses.locate_key("userid", uid)
        ' get key's id and build filename
        Dim filename As String = String.Format("key-{0}-{1}.asc", key.keyid(), If(secret, "sec", "pub")) 
        Dim keyfile As RopOutput = rop.create_output(filename)
        Try
            key.export(keyfile, Not secret, secret, True, True)
        Finally
            rop.drop(keyfile)
        End Try
    End Sub
    
    ' this example function generates RSA/RSA and Eddsa/X25519 keypairs
    Private Sub generate_keys(rop As RopBind)
        Dim alt As Integer = rop.tagging()
        Try
            ' initialize
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            Try
                ' set password provider
                ses.set_pass_provider(Me, Nothing)
                ' generate EDDSA/X25519 keypair
                Dim key_grips As RopData = ses.generate_key_json(New RopData(CURVE_25519_KEY_DESC))
                ' generate RSA keypair
                key_grips = ses.generate_key_json(New RopData(RSA_KEY_DESC))
                Console.WriteLine(String.Format("Generated RSA key/subkey:" & Environment.NewLine & "%s" & Environment.NewLine, key_grips))
            Catch ex As RopError
                Console.WriteLine("Failed to generate keys")
                Throw ex
            End Try

            Dim keyfile As RopOutput = Nothing
            Try
                ' create file output object and save public keyring with generated keys, overwriting
                ' previous file if any. You may use max_alloc here as well.
                keyfile = rop.create_output("pubring.pgp")
                ses.save_keys_public(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine("Failed to save pubring")
                throw ex
            Finally
                rop.drop(keyfile)
            End Try

            keyfile = Nothing
            Try
                ' create file output object and save secret keyring with generated keys
                keyfile = rop.create_output("secring.pgp")
                ses.save_keys_secret(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine("Failed to save secring")
                Throw ex
            Finally
                rop.drop(keyfile)
            End Try
        Finally
            rop.drop(alt)
        End Try
    End Sub

    Private Sub output_keys(rop As RopBind)
        Dim alt As Integer = rop.tagging()
        Try
            ' initialize
            Dim ses As RopSession = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG)

            Dim keyfile As RopInput = Nothing
            Try
                ' load keyrings
                keyfile = rop.create_input("pubring.pgp")
                ' actually, we may exclude the public  to not check key types
                ses.load_keys_public(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine("Failed to read pubring")
                Throw ex
            Finally
                rop.drop(keyfile)
            End Try

            keyfile = Nothing
            Try
                keyfile = rop.create_input("secring.pgp")
                ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile)
            Catch ex As RopError
                Console.WriteLine("Failed to read secring")
                Throw ex
            Finally
                rop.drop(keyfile)
            End Try

            Try
                ' print armored keys to the stdout
                print_key(rop, ses, "rsa@key", false)
                print_key(rop, ses, "rsa@key", true)
                print_key(rop, ses, "25519@key", false)
                print_key(rop, ses, "25519@key", true)
            Catch ex As Exception
                Console.WriteLine("Failed to print armored key(s)")
                Throw ex
            End Try

            Try
                ' write armored keys to the files, named key-<keyid>-pub.asc/named key-<keyid>-sec.asc
                export_key(rop, ses, "rsa@key", false)
                export_key(rop, ses, "rsa@key", true)
                export_key(rop, ses, "25519@key", false)
                export_key(rop, ses, "25519@key", true)
            Catch ex As Exception
                Console.WriteLine("Failed to write armored key(s) to file")
                Throw ex
            End Try
        Finally
            rop.drop_from(alt)
        End Try
    End Sub

    Public Sub execute
        Dim rop As RopBind = New RopBind()
        Try
            generate_keys(rop)
            output_keys(rop)
        Finally
            rop.Close()
        End Try
    End Sub
    
    Shared Sub Main(args As String())
        Dim gen As Generate = New Generate()
        gen.execute()
    End Sub
End Class

End Namespace
