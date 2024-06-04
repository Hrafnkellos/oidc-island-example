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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace exampledotnetopenidconnectclient.Helpers
{
    public class Client
    {
        private static Client instance;
        private static App_Start.AppConfig _config = App_Start.AppConfig.Instance;

        private string client_id;
        private string client_secret;
        private string redirect_uri;
        private string token_endpoint;
        private string issuer;
        private string jwks_uri;
        private string revocation_endpoint;
        private string authorization_endpoint;
        private string scope;
        private string response_type = "code";
        private string code_challenge_method = "S256";
        private (string code_challenge, string verifier) pkce;
        private Dictionary<string, (string code_challenge, string verifier)> state_id_code_challange_map = new Dictionary<string, (string code_challenge, string verifier)>();

        private Client()
        {
            client_id = _config.GetClientId();
            client_secret = _config.GetClientSecret();
            redirect_uri = _config.GetRedirectUri();
            token_endpoint = _config.GetTokenEndpoint();
            issuer = _config.GetIssuer();
            jwks_uri = _config.GetJwksUri();
            revocation_endpoint = _config.GetRevocationEndpoint();
            authorization_endpoint = _config.GetAuthorizationEndpoint();
            scope = _config.GetScope();
        }

        public void Revoke(string refresh_token)
        {
            var values = new Dictionary<string, string>
            {
                { "token", refresh_token },
                { "client_secret", client_secret },
                { "client_id" , client_id }
            };

            HttpClient revokeClient = new HttpClient();
            var content = new FormUrlEncodedContent(values);
            var response = revokeClient.PostAsync(revocation_endpoint, content).Result;

            if (response.IsSuccessStatusCode)
            {
                var responseContent = response.Content;
                string responseString = responseContent.ReadAsStringAsync().Result;

                return;
            }

            throw new OAuthClientException("Could not revoke the refresh token");
        }

        public string Refresh(string refresh_token)
        {
            var values = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refresh_token },
                { "client_secret", client_secret },
                { "client_id" , client_id }
            };

            HttpClient refreshClient = new HttpClient();
            var content = new FormUrlEncodedContent(values);
            var response = refreshClient.PostAsync(token_endpoint, content).Result;

            if (response.IsSuccessStatusCode)
            {
                var responseContent = response.Content;

                return responseContent.ReadAsStringAsync().Result;
            }

            throw new OAuthClientException("Could not refresh the tokens");
        }

        public string GetAuthnReqUrl()
        {
            pkce = Pkce.Generate();
            var stateId = Guid.NewGuid();

            state_id_code_challange_map.Add(stateId.ToString(), pkce);

            return authorization_endpoint + 
                "?client_id=" + client_id + 
                "&response_type=" + response_type  +
                "&scope=" + scope + 
                "&state=" + stateId +
                "&redirect_uri=" + redirect_uri +
                "&code_challenge=" + pkce.code_challenge + 
                "&code_challenge_method=" + code_challenge_method;
        }

        public async Task<string> GetToken(string code, string state)
        {
            bool success = state_id_code_challange_map.TryGetValue(state, out var pkce_pair);

            var values = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code" , code },
                { "code_verifier" , pkce_pair.verifier },
                { "redirect_uri", redirect_uri}
            };

            HttpClient httpClient = new HttpClient();
            var content = new FormUrlEncodedContent(values);

            var authenticationString = $"{client_id}:{client_secret}";
            var base64EncodedAuthenticationString = Base64Encode(authenticationString);

            //Post body content
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, token_endpoint);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", base64EncodedAuthenticationString);
            requestMessage.Content = content;

            //make the request
            var response = await httpClient.SendAsync(requestMessage);
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseBody);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = response.Content;

                return responseContent.ReadAsStringAsync().Result;
            }

            throw new OAuthClientException("Token request failed with status code: " + response.StatusCode);
        }

        public static Client Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new Client();
                }
                return instance;
            }
        }
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}


/// <summary>
/// Provides a randomly generating PKCE code verifier and it's corresponding code challenge.(PKCE sometimes called pixy)
/// </summary>
public static class Pkce
{
    /// <summary>
    /// Generates a code_verifier and the corresponding code_challenge, as specified in the rfc-7636.
    /// </summary>
    /// <remarks>See https://datatracker.ietf.org/doc/html/rfc7636#section-4.1 and https://datatracker.ietf.org/doc/html/rfc7636#section-4.2</remarks>
    public static (string code_challenge, string verifier) Generate(int size = 32)
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        var randomBytes = new byte[size];
        rng.GetBytes(randomBytes);
        var verifier = Base64UrlEncode(randomBytes);

        var buffer = Encoding.UTF8.GetBytes(verifier);
        var hash = SHA256.Create().ComputeHash(buffer);
        var challenge = Base64UrlEncode(hash);

        return (challenge, verifier);
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
}