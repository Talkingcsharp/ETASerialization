/*
 *  Copyright 2017-2018 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

 /*
  *  Written for the Pkcs11Interop project by:
  *  Jaroslav IMRICH <jimrich@jimrich.sk>
  */
 
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace JsonHashing.WebApi
{
    public class TokenRSA : RSA
    {
        private readonly X509Certificate2 _certificate;
        private readonly ISession _session;
        private readonly ISlot _slot;
        private readonly IObjectHandle _privateKeyHandle;

        public TokenRSA(X509Certificate2 certificate, ISession session, ISlot slot, IObjectHandle privateKeyHandle)
        {
            _certificate = certificate;
            _session = session;
            _slot = slot;
            _privateKeyHandle = privateKeyHandle;
        }


        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            if (padding == RSASignaturePadding.Pkcs1)
            {
                byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm);
                if (pkcs1DigestInfo == null)
                    throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

                
                using (IMechanism mechanism = _session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS))
                {
                    return _session.Sign(mechanism, _privateKeyHandle, pkcs1DigestInfo);
                }
            }
            else if (padding == RSASignaturePadding.Pss)
            {
                IMechanismParamsFactory mechanismParamsFactory = _slot.Factories.MechanismParamsFactory;

                ICkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(mechanismParamsFactory, hash, hashAlgorithm);
                if (pssMechanismParams == null)
                    throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

                
                using (IMechanism mechanism = _session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams))
                {
                    
                        return _session.Sign(mechanism, _privateKeyHandle, hash);
                }
            }
            else
            {
                throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
            }
        }

       
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
                throw new NotSupportedException("Private key export is not supported");

            RSA rsaPubKey = _certificate.GetRSAPublicKey();
            return rsaPubKey.ExportParameters(false);
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException("Key import is not supported");
        }

        private static byte[] CreatePkcs1DigestInfo(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            byte[] pkcs1DigestInfo = null;

            if (hashAlgorithm == HashAlgorithmName.MD5)
            {
                if (hash.Length != 16)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }

            return pkcs1DigestInfo;
        }


        private static ICkRsaPkcsPssParams CreateCkRsaPkcsPssParams(IMechanismParamsFactory mechanismParamsFactory, byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            ICkRsaPkcsPssParams pssParams = null;

            if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA_1,
                    mgf: (ulong)CKG.CKG_MGF1_SHA1,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA256,
                    mgf: (ulong)CKG.CKG_MGF1_SHA256,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA384,
                    mgf: (ulong)CKG.CKG_MGF1_SHA384,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = mechanismParamsFactory.CreateCkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA512,
                    mgf: (ulong)CKG.CKG_MGF1_SHA512,
                    len: (ulong)hash.Length
                );
            }

            return pssParams;
        }
    }
}