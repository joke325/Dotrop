using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using tech.janky.dotrop.examples;


namespace tech.janky.dotrop.tests {

[TestFixture]
public class RopExamplesTest {
    private List<string> test_key_ids;

    [OneTimeSetUp]
    public void setUp() {
        foreach(string fname in new String[] {"pubring.pgp", "secring.pgp"}) {
            try {
                File.Delete(fname);
            } catch(IOException) {}
        }
        test_key_ids = new List<string>();
    }
    
    [OneTimeTearDown]
    public void tearDown() {
        List<string> fnames = new List<string>();
        foreach(string name in new string[] {"pubring.pgp", "secring.pgp", "encrypted.asc", "signed.asc"})
            fnames.Add(name);
        foreach(string keyid in test_key_ids) {
            fnames.Add(string.Format("key-{0}-pub.asc", keyid));
            fnames.Add(string.Format("key-{0}-sec.asc", keyid));
        }
        foreach(string fname in fnames) {
            try {
                File.Delete(fname);
            } catch(IOException) {}
        }
    }

    [Test]
    public void test_examples() {
        //Execute
        (new Generate()).execute();
        (new Encrypt()).execute();
        (new Decrypt()).execute();
        if(Encrypt.message.CompareTo(Decrypt.message) != 0)
            throw new Exception("Decryption Failed!");
        (new Sign()).execute();
        for(int idx = 0; idx < 2; idx++)
            test_key_ids.Add(Sign.key_ids[idx]);
        (new Verify()).execute();
        string[] out_ = new string[] {null}; 
        (new Dump()).execute(new string[] {"Dump", "-j", "signed.asc"}, out_);

        //Parse the dump
        JArray jso = null, ref_jso = null;
        try {
            jso = JArray.Parse(out_[0]);
        } catch(JsonReaderException) {
            Assert.True(false);
        }
        
        String data = null;
        try {
        	data = File.ReadAllText("et_json.txt");
        } catch(IOException) {
	        Assert.IsTrue(false);
        }
        data = data.Replace("b2617b172b2ceae2a1ed72435fc1286cf91da4d0", Sign.key_fprints[0].ToLower());
        data = data.Replace("5fc1286cf91da4d0", Sign.key_ids[0].ToLower());
        data = data.Replace("f1768c67ec5a9ead3061c2befeee14c57b1a12d9", Sign.key_fprints[1].ToLower());
        data = data.Replace("feee14c57b1a12d9", Sign.key_ids[1].ToLower());
        try {
            ref_jso = JArray.Parse(data);
        } catch(JsonReaderException) {
            Assert.IsTrue(false);
        }

        // Compare the jsons
        right_cmp_json(jso, ref_jso);

        TestContext.Progress.WriteLine("SUCCESS !");
    }
    
    private void right_cmp_json(object json, object ref_json) {
        if(typeof(JArray).IsInstanceOfType(ref_json))
            for(int idx = 0; idx < ((JArray)ref_json).Count; idx++) 
                right_cmp_json(((JArray)json)[idx], ((JArray)ref_json)[idx]);
        else if(typeof(JObject).IsInstanceOfType(ref_json)) {
            foreach(JProperty prop in ((JObject)ref_json).Properties())
                right_cmp_json(((JObject)json)[prop.Name], prop.Value);
        } else if(!json.Equals(ref_json))
            throw new Exception(string.Format("FAILED! ({0} != {1})", json, ref_json));
    }
}

}
