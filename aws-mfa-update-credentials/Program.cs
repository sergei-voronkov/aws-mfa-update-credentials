namespace aws_mfa_update_credentials
{
    using Amazon.Runtime;
    using Amazon.SecurityToken;
    using Amazon.SecurityToken.Model;
    using IniParser;
    using IniParser.Model;
    using Newtonsoft.Json;
    using System.Text;

    internal class Program
    {
        static async Task Main(string[] args)
        {
            string tokenCode = GetTokenCode(args);

            FileIniDataParser credentialsIni = new();

            IniData credentialsIniData = credentialsIni.ReadFile(
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".aws/credentials.default"));

            KeyDataCollection section = credentialsIniData["default"];

            string keyId = section["aws_access_key_id"];
            string accessKey = section["aws_secret_access_key"];
            string serialNumber = section["carat_serial_number"];

            BasicAWSCredentials credentials = new(
                keyId,
                accessKey);

            AmazonSecurityTokenServiceClient sts = new(credentials);

            GetSessionTokenResponse getSessionTokenResponse = await sts.GetSessionTokenAsync(
                new GetSessionTokenRequest
                {
                    SerialNumber = serialNumber,
                    DurationSeconds = 129600,
                    TokenCode = tokenCode
                });

            Console.WriteLine(
                JsonConvert.SerializeObject(
                    getSessionTokenResponse,
                    Formatting.Indented));

            if (getSessionTokenResponse.HttpStatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new Exception(
                    "Unable to get session token.");
            }

            SectionData targetSection = new("default");

            targetSection.Keys["output"] = "json";
            targetSection.Keys["region"] = "us-east-1";
            targetSection.Keys["aws_access_key_id"] = getSessionTokenResponse.Credentials.AccessKeyId;
            targetSection.Keys["aws_secret_access_key"] = getSessionTokenResponse.Credentials.SecretAccessKey;
            targetSection.Keys["aws_session_token"] = getSessionTokenResponse.Credentials.SessionToken;

            IniData targetData = new();
            targetData.Sections.Add(
                targetSection);

            FileIniDataParser targetCredentialsIni = new();


            string targetIniPath =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".aws/credentials");

            targetCredentialsIni.WriteFile(
                targetIniPath,
                targetData,
                Encoding.ASCII);
        }

        private static string GetTokenCode(string[] args)
        {
            if (args.Length < 1)
            {
                throw new ArgumentException(
                    "Specify token code from Google Authentificator as the first parameter");
            }

            return args[0];
        }
    }
}