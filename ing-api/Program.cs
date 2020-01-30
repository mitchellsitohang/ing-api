using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ing_api
{
    class Program
    {
        static async System.Threading.Tasks.Task Main(string[] args)
        {
            string reqPath = "/oauth2/token";
            string host = "https://api.sandbox.ing.com";
            string myURL = $"{host}{reqPath}";

            var certFolder = @"D:\ing\certs\";
            var signingCert = @"example_client_signing.pfx"; // signs the request 
            var tlsCert = @"example_client_tls.pfx"; // encrypts (and signs) the connection between http and tcp/ip

            DateTime requestDate = DateTime.UtcNow;
            string requestDateText = requestDate.ToString("R");//"Thu, 30 Jan 2020 13:56:13 GMT";
            string digest = "SHA-256=w0mymuL8aCrbJmmabs1pytZhon8lQucTuJMUtuKr+uw=";
            string signingString = $"(request-target): {"post"} {reqPath}\ndate: {requestDateText}\ndigest: {digest}";

            string signature = null;

            X509Certificate2 httpCert = new X509Certificate2(Path.Combine(certFolder, signingCert));
            using (RSA rsa = httpCert.GetRSAPrivateKey())
            {
                byte[] byteSignature = rsa.SignData(Encoding.ASCII.GetBytes(signingString), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                signature = Convert.ToBase64String(byteSignature);
            }

            X509Certificate2 cert = new X509Certificate2(Path.Combine(certFolder, tlsCert));

            var shHandler = new SocketsHttpHandler();
            shHandler.SslOptions = new SslClientAuthenticationOptions();
            shHandler.SslOptions.ClientCertificates = new X509CertificateCollection();
            shHandler.SslOptions.ClientCertificates.Add(cert);
            shHandler.SslOptions.LocalCertificateSelectionCallback = (object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers) => cert;

            var client = new HttpClient(shHandler);
            
            // For Guillaume
            // var a = client.DefaultRequestHeaders;
            // Console.WriteLine(a);

            var payload = new Dictionary<string, string>();
            payload.Add("grant_type", "client_credentials");
            var content = new FormUrlEncodedContent(payload);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, myURL);
            request.Content = content;

            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Digest", digest);
            request.Headers.Add("Date", requestDateText);
            request.Headers.Add("authorization", $"Signature keyId=\"e77d776b-90af-4684-bebc-521e5b2614dd\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest\",signature=\"{signature}\"");

            Console.WriteLine(request);
            var response = await client.SendAsync(request);

            Console.WriteLine(response);
            Console.WriteLine(await response.Content.ReadAsStringAsync());

            Console.ReadKey();
        }
    }
}
