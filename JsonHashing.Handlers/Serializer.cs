/* 
 * This sample was created by Mohammed S. Elsuissey
 * Software consultant and .Net developer
 * asegypt@gmail.com
 * 01000592036
 */
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace JsonHashing.Handlers
{
    public class Serializer
    {
        public string Serialize(JsonDocument document)
        {
            return SerializeToken(document.RootElement);
        }

        private string SerializeToken(JsonElement request, string? parentName = null)
        {
            string serialized = "";
            switch (request.ValueKind)
            {
                case JsonValueKind.Object :
                    foreach (var item in request.EnumerateObject())
                    {
                        serialized += "\"" + item.Name.ToUpper() + "\"";
                        serialized += SerializeToken(item.Value , item.Name.ToUpper());
                    }
                    break;
                case JsonValueKind.Array:
                    foreach (var item in request.EnumerateArray())
                    {
                        serialized += "\"" + parentName + "\"";
                        serialized += SerializeToken(item);
                    }
                    break;
                case JsonValueKind.Null:
                case JsonValueKind.Undefined :
                    throw new Exception($" error while serializing : {request}");
                default:
                    serialized += "\"" + request + "\"";
                    break;
            }
            return serialized;
        }

    }
}
