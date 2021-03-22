/* 
 * This sample was created by Mohammed S. Elsuissey
 * Software consultant and .Net developer
 * asegypt@gmail.com
 * 01000592036
 */
using JsonHashing.Handlers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JsonHashing.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InvoiceHasher : ControllerBase
    {
        private readonly Serializer _serializer;
        private readonly Hasher _hasher;
        private readonly IConfiguration _configuration;


        private readonly string DllLibPath = "eps2003csp11.dll";

        private readonly string TokenPin = "23278181";

        public InvoiceHasher(Serializer serializer, Hasher hasher, IConfiguration configuration)
        {
            _serializer = serializer;
            _hasher = hasher;
            _configuration = configuration;
        }

        [HttpPost("[action]")]
        public async Task<string> Serialize()
        {
            using (StreamReader sr = new StreamReader(Request.Body))
            {
                string requestbody = await sr.ReadToEndAsync();
                JObject request = JsonConvert.DeserializeObject<JObject>(requestbody,new JsonSerializerSettings()
                {
                      FloatFormatHandling = FloatFormatHandling.String,
                       FloatParseHandling = FloatParseHandling.Decimal,
                       DateFormatHandling= DateFormatHandling.IsoDateFormat,
                        DateParseHandling = DateParseHandling.None
                });
                var h = _serializer.Serialize(request);
                return h;
            };
        }

        [HttpPost("[action]")]
        public async Task<ActionResult<byte[]>> Hash()
        {
            using (StreamReader sr = new StreamReader(Request.Body))
            {
                string requestbody = await sr.ReadToEndAsync();
                //var hashed = _hasher.Hash(requestbody);

                return Ok(SignWithCMS(Encoding.UTF8.GetBytes(requestbody)));
            };
        }


        [HttpGet]
        public ActionResult GetAllCerts()
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
            {
                ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();

                if (slot is null)
                {
                    return Ok("No slots found");
                }

                

                ITokenInfo tokenInfo = slot.GetTokenInfo();

                ISlotInfo slotInfo = slot.GetSlotInfo();

                using (var session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(TokenPin));

                    
                    var certificateSearchAttributes = new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                    };

                    IObjectHandle certificate = session.FindAllObjects(certificateSearchAttributes).FirstOrDefault();

                    var certificateValue = session.GetAttributeValue(certificate, new List<CKA>
                    {
                        CKA.CKA_VALUE
                    });


                    var xcert = new X509Certificate2(certificateValue[0].GetValueAsByteArray());

                    return Ok(

                        new
                        {
                            xcert.Thumbprint,
                            xcert.Subject,
                            xcert.IssuerName,
                            hasKeyNull = xcert.PrivateKey is null
                        });

                    if (certificate is null)
                    {
                        return Ok("Certificate not found");
                    }
                    JArray output = new JArray();
                    foreach (string location in Enum.GetNames(typeof(StoreLocation)))
                    {
                        foreach (string name in Enum.GetNames(typeof(StoreName)))
                        {
                            using (var store = new X509Store(Enum.Parse<StoreName>(name), Enum.Parse<StoreLocation>(location)))
                            {
                                store.Open(OpenFlags.MaxAllowed);
                                foreach (var cert in store.Certificates.Find(X509FindType.FindByIssuerName, "Egypt Trust Sealing CA", true))
                                {
                                    output.Add(JObject.FromObject(new
                                    {
                                        location,
                                        name,
                                        cert.IssuerName.Name,
                                        cert.FriendlyName,
                                        Privatekey = cert.PrivateKey == null
                                    }));
                                }
                                store.Close();
                            }
                        }
                    }
                    return Ok(output.ToString());
                }
            }
        }
        private string SignWithCMS(byte[] data)
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
            {
                ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();

                if (slot is null)
                {
                    return "No slots found";
                }


                using (var session = slot.OpenSession(SessionType.ReadWrite))
                {

                    session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(TokenPin));

                    var searchAttribute = new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                    };

                    IObjectHandle certificate = session.FindAllObjects(searchAttribute).FirstOrDefault();


                    if (certificate is null)
                    {
                        return "Certificate not found";
                    }

                    var attributeValues = session.GetAttributeValue(certificate, new List<CKA>
                    {
                        CKA.CKA_VALUE
                    });


                    var xcert = new X509Certificate2(attributeValues[0].GetValueAsByteArray());

                    searchAttribute = new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE,CKK.CKK_RSA)
                    };

                    IObjectHandle privateKeyHandler = session.FindAllObjects(searchAttribute).FirstOrDefault();

                    RSA privateKey = new TokenRSA(xcert, session, slot, privateKeyHandler);
                    //privateKey.ImportRSAPublicKey(_cspBlob, out _);

                    //searchAttribute = new List<IObjectAttribute>()
                    //{
                    //    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    //    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE,CKK.CKK_RSA)
                    //};

                    //IObjectHandle privateKeyHandler = session.FindAllObjects(searchAttribute).FirstOrDefault();

                    //attributeValues = session.GetAttributeValue(privateKeyHandler, new List<CKA> { 
                    //    CKA.CKA_VALUE 
                    //});

                    //RSA privateKey = RSA.Create();
                    //privateKey.ImportRSAPrivateKey(attributeValues[0].GetValueAsByteArray(), out _);





                    ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);


                    SignedCms cms = new SignedCms(content, true);


                    EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), _hasher.HashBytes(xcert.RawData));

                    SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });


                    CmsSigner signer = new CmsSigner(xcert);

                    signer.PrivateKey = privateKey;

                    signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");



                    signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
                    signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));

                    cms.ComputeSignature(signer);

                    var output = cms.Encode();

                    return Convert.ToBase64String(output);
                }
            }
           
        }

    }
}
