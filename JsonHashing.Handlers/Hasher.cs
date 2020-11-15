using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JsonHashing.Handlers
{
    public class Hasher
    {
        public byte[] Hash(string input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
                return output;
            }
        }

        public byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(input);
                return output;
            }
        }
    }
}
