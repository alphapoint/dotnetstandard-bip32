using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Chaos.NaCl;

namespace dotnetstandard_bip32_4._5._2
{
    public class BIP32
    {
        readonly string curve = "ed25519 seed";
        readonly uint hardenedOffset = 0x80000000;

        public GetKeyFromSeedResponse GetMasterKeyFromSeed(string seed)
        {
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Encoding.UTF8.GetBytes(curve)))
            {
                var i = hmacSha512.ComputeHash(seed.HexToByteArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                return new GetKeyFromSeedResponse{Key=il, ChainCode=ir};
            }
        }

        private GetKeyFromSeedResponse GetChildKeyDerivation(byte[] key, byte[] chainCode, uint index)
        {
            BigEndianBuffer buffer = new BigEndianBuffer();

            buffer.Write(new byte[] { 0 });
            buffer.Write(key);
            buffer.WriteUInt(index);

            using (HMACSHA512 hmacSha512 = new HMACSHA512(chainCode))
            {
                var i = hmacSha512.ComputeHash(buffer.ToArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                return new GetKeyFromSeedResponse{Key=il, ChainCode = ir};
            }
        }

        public byte[] GetPublicKey(byte[] privateKey, bool withZeroByte = true)
        {
            Ed25519.KeyPairFromSeed(out var publicKey, out _, privateKey);

            var zero = new byte[] { 0 };

            var buffer = new BigEndianBuffer();
            if (withZeroByte)
                buffer.Write(zero);

            buffer.Write(publicKey);

            return buffer.ToArray();
        }

        private bool IsValidPath(string path)
        {
            var regex = new Regex("^m(\\/[0-9]+')+$");

            if (!regex.IsMatch(path))
                return false;

            var valid = !(path.Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Any(a => !Int32.TryParse(a, out _)));

            return valid;
        }


        public GetKeyFromSeedResponse DerivePath(string path, string seed)
        {
            if (!IsValidPath(path))
                throw new FormatException("Invalid derivation path");

            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);

            var segments = path
                .Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Select(a => Convert.ToUInt32(a, 10));

            var results = segments
                .Aggregate(masterKeyFromSeed, (mks, next) => GetChildKeyDerivation(mks.Key, mks.ChainCode, next + hardenedOffset));

            return results;
        }


    }

    public class GetKeyFromSeedResponse
    {
        public byte[] Key { get; set; }
        public byte[] ChainCode { get; set; }
    }
}
