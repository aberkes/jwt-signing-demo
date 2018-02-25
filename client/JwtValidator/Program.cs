using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace JwtValidator
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6IkRlbW8gSXNzdWVyIG1vZGlmaWVkIiwiZXhwIjoxNTUxMDg2MjI0LCJpYXQiOjE1MTk1NTAyMjR9.nrm_8kPViupY20XQ5JJRMOlTdbydsBzmbBIasImYQRQrYtoweFQ39sPgh5HfCHLPpJHTG_PLTY5iSWXeT5nh6-fI_4n81xKIROw6OlYXIFSedxFI8bVmYXMtvTE37Y_7tBqfTAhS4CmcAYiggtuyguACNOzVNx2MKZkCOUAuLvpYcUY4Y8dJ1-AkXOBTaIUp11ICO8OPjtWn6FQaWG6MIFCc62GYZzDuI28OirFvSb2ZI9XZSxTETeZ4t7gACS1coqKNmlY4qSpExNCxSzoHRKdtIkQDXZLnk7N6RNxW1dMLpsRxqKBxV_h20wJrCavnA2I1PwzD8yeN1u1mr3G-Ew";
                //string publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoiIoChU/Rmpjg82FL7q9dmdC6Jw+CgeXv2k/v4xFdD8EuGnt/xq+4Zt9IPRKozBqBlS6wwgsiFa2y0l+crTaloIjc+FctdlxTYYka4OlQIACeyaIVQ7JJaajwX/Z1WKpGyKSqiH6+Qg3flkER5epK1gNs9fXQU/noKFhPu2pyfng/3vc0xaIZO46IWMinAFQBlxtSN7UWKKaDDTno/cawaHM3xhzJChAnLgHfSVHYl2g12+j4kzXVDMmoqF6nIGHcFBU/Vun0YrdJ/5KjaSr20EfIHvAVR9aa/rN3OlveuKr8oIMpTA+xbwQ8FeVIpERU6eg2OSGMY3HrTbGNV7eHQIDAQAB";

                string jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3IiwiaXNzIjoiTm9QYXNzIE1vYmlsZSBBcHAiLCJleHAiOiIxNTUwOTI0MDcxIiwiYXVkIjoiTG9nTWVJbiBSZXNjdWUiLCJlbWFpbCI6ImlzdHZhbi5yZWl0ZXJAbG9nbWVpbi5jb20iLCJjb25uZWN0aW9uSWQiOiJkYXRhLmRhdGEudG9TdHJpbmcoKSJ9.PKlO2by_Wi7H5mWuHqph-qCGUMHawcHP1sGkyw4RjbjYqZVbix12cHlxfgUdap0gRAiK1OWBgvG5vxcj0jlNLDt866IzCiuLn_RLQBTaSSeKRQ05l7w3uqBIBDwgWZi2oljRPUEr1PpAviquoht56h0Q3oesytXDKMKidmCSIC5ban7u9BWoLHgs3dtVR6eXMq-KWEHcL6MIyl5vNV5Sfh2nP-5175pPiOm037nzmuoT1Q2AztFiRbXb4XRbzDTu5776VYww9KNbXiQ7zrZTtf0JaxaYwN0Fc0F1NTSQZZ30x1LXmHLnA2i8ZxUODX3k1hyUnPfKzHx6NVspcbreOA";
                string publicKey = "MIIBCgKCAQEAtMfrJULay5tGI2ujTF+d8wZQ1RkNCMO+YOOEQEEiW4u2WmVazkUeyYJbGnfOtrGPQHTUkAbl3WFCqQdTp5+SfPjrSZ+O5ngteCjC8YDmQMEueOLxPg3bavlwRbvV8hh/WwP5ZHqL1L54n8CGoQkkU8zQYjAE4SC9LJyQtL1kiV2VbP2yx+13uJ+cvvA9NOw5YEGYkGo4Ro6jlyQClkF9MrPKH0ZO5S9KaO5/hKXPoZd23uIbgOioEyxiTH/g7ktyB71Je+to71ljuVx20aoFe5FBKhmL+XfZhcckwCc/sCMgbxp6s8LehYGpl2RSEg95qf3rX+7L28Jwcf3piTXddQIDAQAB";

                VerifyPubKey(jwt, publicKey);

                //if (args.Length > 0)
                //{
                //    switch (args[0].ToLower())
                //    {
                //        case "verify":
                //            VerifyPubKey(args[1], args[2]);
                //            break;
                //    }
                //}
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: " + ex.Message);
            }

            //string pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0PYUqMcp+xS5fJ6SqMgtroafrsHNkHrMCPR3LtuU6rygsXxTmndQKe80qjlnw1VSL/ol1oTcZyqFolp//CH7ksnMDP68sgZDF+qPC307nxhzguNDfGJa/JaciBQPXU9SaPR5lFtbD7XGp6/fe+lcMHFSOWylnNhrnlmzTr2/nqLOBBiR6iz6un5RH0C7AwZXXGNr38MPZZ68oiXMZvTUwDgndMEzFtrtHbGm7Q8a9USpeOJwkrnzNtbu5licXOul2lc9BJHjv/CTIi0mAxp5LSQRaQUPDbdBGCF0SLL++hlWpVLmjRfHyBoGV+edcj+LkUZXGuC/QvA4kOUIX7JYuwIDAQAB";

            //try
            //{
            //    var securityKey = new X509AsymmetricSecurityKey(new X509Certificate2(Convert.FromBase64String(pubKey)));
            //    Console.WriteLine("Certificate created successfully.");
            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine($"Error during creating certificate. Error: {ex.Message}");
            //}

            Console.ReadKey();
        }

        static void VerifyPubKey(string jwt, string key)
        {
            string[] parts = jwt.Split('.');
            string header = parts[0];
            string payload = parts[1];
            byte[] crypto = Base64UrlDecode(parts[2]);

            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            JObject headerData = JObject.Parse(headerJson);

            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            JObject payloadData = JObject.Parse(payloadJson);

            var keyBytes = Convert.FromBase64String(key);

            //var rsaParameters = GetRsaParametersForX509(keyBytes);
            var rsaParameters = GetRsaParametersForPKCS1(keyBytes);
            
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
                Console.WriteLine("Invalid signature");
            else
                Console.WriteLine("Congrats! Signature is valid!");
        }

        private static RSAParameters GetRsaParametersForX509(byte[] keyBytes)
        {
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();

            return rsaParameters;
        }

        private static RSAParameters GetRsaParametersForPKCS1(byte[] keyBytes)
        {
            Asn1Object obj = Asn1Object.FromByteArray(keyBytes);
            DerSequence publicKeySequence = (DerSequence)obj;

            DerInteger modulus = (DerInteger)publicKeySequence[0];
            DerInteger exponent = (DerInteger)publicKeySequence[1];

            RsaKeyParameters keyParameters = new RsaKeyParameters(false, modulus.PositiveValue, exponent.PositiveValue);

            return DotNetUtilities.ToRSAParameters(keyParameters);
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                    .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        // from JWT spec
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
