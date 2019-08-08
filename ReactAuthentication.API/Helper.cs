using System;
using System.Security.Cryptography;
using System.Text;

namespace ReactAuthentication.API
{
    public class Helper
    {
        public static string GetHash(string clientSecret)
        {
            using (SHA256CryptoServiceProvider sha256 = new SHA256CryptoServiceProvider())
            {
                byte[] byteValue = Encoding.UTF8.GetBytes(clientSecret);
                byte[] byteHash = sha256.ComputeHash(byteValue);

                return Convert.ToBase64String(byteHash);
            }
        }
    }
}