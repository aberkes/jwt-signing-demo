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

namespace JwtValidator
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                switch (args[0].ToLower())
                {
                    case "verify":
                        VerifyPubKey(args[1], args[2]);
                        break;
                }
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

            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
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
