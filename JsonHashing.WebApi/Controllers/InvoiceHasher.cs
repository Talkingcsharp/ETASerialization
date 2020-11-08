/* 
 * This sample was created by Mohammed S. Elsuissey
 * Software consultant and .Net developer
 * asegypt@gmail.com
 * 01000592036
 */
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using JsonHashing.Handlers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JsonHashing.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InvoiceHasher : ControllerBase
    {
        private readonly Serializer _serializer;

        public InvoiceHasher(Serializer serializer)
        {
            _serializer = serializer;
        }

        [HttpPost("[action]")]
        public async Task<string> Serialize()
        {
            using (StreamReader sr = new StreamReader(Request.Body))
            {
                string requestbody = await sr.ReadToEndAsync();
                JObject request = JsonConvert.DeserializeObject<JObject>(requestbody);
                var h = _serializer.Serialize(request);
                return h;
            };
        }
    }
}
