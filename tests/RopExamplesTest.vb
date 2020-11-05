Imports System
Imports System.Collections.Generic
Imports System.IO
Imports NUnit.Framework
Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq
Imports tech.janky.dotrop.examples_vb


Namespace tech.janky.dotrop.tests

<TestFixture>
Public Class RopExamplesTest_VB
    Private test_key_ids As List(Of String)

    <OneTimeSetUp>
    Public Sub setUp()
        For Each fname As String In New String() {"pubring.pgp", "secring.pgp"}
            Try
                File.Delete(fname)
            Catch ex As IOException
            End Try
        Next
        test_key_ids = New List(Of String)()
    End Sub
    
    <OneTimeTearDown>
    Public Sub tearDown()
        Dim fnames As List(Of String) = New List(Of String)()
        For Each name As String In New String() {"pubring.pgp", "secring.pgp", "encrypted.asc", "signed.asc"}
            fnames.Add(name)
        Next
        For Each keyid As String In test_key_ids
            fnames.Add(String.Format("key-{0}-pub.asc", keyid))
            fnames.Add(String.Format("key-{0}-sec.asc", keyid))
        Next
        For Each fname As String In fnames
            Try
                File.Delete(fname)
            Catch ex As IOException
            End Try
        Next
    End Sub

    <Test>
    Public Sub test_examples()
        'Execute
        Call New Generate().execute()
        Call New Encrypt().execute()
        Call New Decrypt().execute()
        If Encrypt.message.CompareTo(Decrypt.message) <> 0 Then
            Throw New Exception("Decryption Failed!")
        End If
        Call New Sign().execute()
        For idx As Integer = 0 To 2-1
            test_key_ids.Add(Sign.key_ids(idx))
        Next
        Call New Verify().execute()
        Dim out_() As String = New string() {Nothing}
        Call New Dump().execute(New String() {"Dump", "-j", "signed.asc"}, out_)

        'Parse the dump
        Dim jso As JArray = Nothing, ref_jso As JArray = Nothing
        Try
            jso = JArray.Parse(out_(0))
        Catch ex As JsonReaderException
            Assert.True(False)
        End Try
        
        Dim data As String = Nothing
        Try
        	data = File.ReadAllText("et_json.txt")
        Catch ex As IOException
	        Assert.IsTrue(False)
        End Try
        data = data.Replace("b2617b172b2ceae2a1ed72435fc1286cf91da4d0", Sign.key_fprints(0).ToLower())
        data = data.Replace("5fc1286cf91da4d0", Sign.key_ids(0).ToLower())
        data = data.Replace("f1768c67ec5a9ead3061c2befeee14c57b1a12d9", Sign.key_fprints(1).ToLower())
        data = data.Replace("feee14c57b1a12d9", Sign.key_ids(1).ToLower())
        Try
            ref_jso = JArray.Parse(data)
        Catch ex As JsonReaderException
            Assert.IsTrue(False)
        End Try

        ' Compare the jsons
        right_cmp_json(jso, ref_jso)

        TestContext.Progress.WriteLine("SUCCESS !")
    End Sub
    
    Private Sub right_cmp_json(json As Object, ref_json As Object)
        If TypeOf ref_json Is JArray Then
            For idx As Integer = 0 To ref_json.Count-1
                right_cmp_json(json(idx), ref_json(idx))
            Next
        Else If TypeOf ref_json Is JObject Then
            For Each prop As JProperty In ref_json
                right_cmp_json(json(prop.Name), prop.Value)
            Next
        Else If Not json.Equals(ref_json) Then
            Throw New Exception(String.Format("FAILED! ({0} != {1})", json, ref_json))
        End If
    End Sub
End Class

End Namespace
