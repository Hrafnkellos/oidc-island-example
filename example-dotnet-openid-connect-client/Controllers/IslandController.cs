/*
 * Copyright (C) 2017 Curity AB.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json.Linq;
using static System.Convert;

namespace exampledotnetopenidconnectclient.Controllers
{
    public class IslandController : Controller
    {
        private static Helpers.Client _client = Helpers.Client.Instance;
        private string issuer = App_Start.AppConfig.Instance.GetIssuer();
        private string jwks_uri = App_Start.AppConfig.Instance.GetJwksUri();

        private JObject id_token_obj;
        private  readonly Dictionary<string, JToken> id_token_dict = new Dictionary<string, JToken>();

        private readonly HttpClient client = new HttpClient();

        public async Task<ActionResult> Index()
        {
            try
            {
                string responseString = await _client.GetToken(Request.QueryString["code"]);
                SaveDataToSession(responseString);
            }
            catch (JwtValidationException e)
            {
                Session["error"] = e.Message;
            }
            catch (OAuthClientException e)
            {
                Session["error"] = e.Message;
            }

            return Redirect("/");
        }

        public void SaveDataToSession(string curityResponse)
        {
            JObject jsonObj = JObject.Parse(curityResponse);

            Session["access_token"] = jsonObj.GetValue("access_token");
            Session["refresh_token"] = jsonObj.GetValue("refresh_token");
            Session["scope"] = jsonObj.GetValue("scope");

            if (jsonObj.GetValue("id_token") != null && IsJwtValid(jsonObj.GetValue("id_token").ToString()))
            {
                Session["id_token"] = jsonObj.GetValue("id_token");
                Session["id_token_json0"] = id_token_obj.GetValue("decoded_header").ToString();
                Session["id_token_json1"] = id_token_obj.GetValue("decoded_payload").ToString();
            }
        }


        public string SafeDecodeBase64(string str)
        {
            return Encoding.UTF8.GetString(
                getPaddedBase64String(str));
        }

        private byte[] getPaddedBase64String(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0 ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return FromBase64String(base64);
        }

        public bool IsJwtValid(string jwt)
        {
            string[] jwtParts = jwt.Split('.');

            string decodedHeader = SafeDecodeBase64(jwtParts[0]);
            string decodedPayload = SafeDecodeBase64(jwtParts[1]);
            id_token_obj = new JObject
            {
                {"decoded_header", decodedHeader },
                {"decoded_payload", decodedPayload }
            };

            string keyId = JObject.Parse(decodedHeader).GetValue("kid").ToString();
            bool keyFound = id_token_dict.TryGetValue(keyId, out var key);

            if (!keyFound)
            {
                key = FetchKeys(keyId);
                if (key == null)
                {
                    throw new JwtValidationException("Key not found in JWKS endpoint or Application State");
                }
            }

            if (!JObject.Parse(decodedPayload).GetValue("iss").ToString().Equals(issuer))
            {
                throw new JwtValidationException("Issuer not validated");
            }

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters()
                {
                    Modulus = getPaddedBase64String(key["n"].ToString()),
                    Exponent = getPaddedBase64String(key["e"].ToString())
                });

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(jwtParts[0] + '.' + jwtParts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, getPaddedBase64String(jwtParts[2])))
            {
                return true; //Jwt Validated
            }
            else
            {
                throw new JwtValidationException("Could not validate signature of JWT");

            }
        }

        public JToken FetchKeys(string keyId)
        {
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var response = client.GetAsync(jwks_uri).Result;

            if (response.IsSuccessStatusCode)
            {
                var responseContent = response.Content;
                string responseString = responseContent.ReadAsStringAsync().Result;

                foreach (JToken key in JObject.Parse(responseString).GetValue("keys").ToArray())
                {
                    if (key["kid"].ToString().Equals(keyId))
                    {
                        id_token_dict.Add(keyId, key);

                        return key;
                    }
                }

                throw new JwtValidationException("Key not found in JWKS endpoint");
            }

            throw new JwtValidationException("Could not contact JWKS endpoint");
        }
    }
}
