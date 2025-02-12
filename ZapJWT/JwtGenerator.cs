using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ZapJWT
{
    public class JwtGenerator
    {
        /// <summary>
        /// 1. 產生 RSA 私鑰 (包含公鑰資訊)，預設 keySize 為 2048 bits
        /// </summary>
        /// <param name="keySize">金鑰長度，預設 2048</param>
        /// <returns>RSACryptoServiceProvider 物件</returns>
        public static RSACryptoServiceProvider GeneratePrivateKey(int keySize = 2048)
        {
            var rsa = new RSACryptoServiceProvider(keySize);
            return rsa;
        }


        /// <summary>
        /// 以 ASN.1 INTEGER 格式寫入位元組資料
        /// </summary>
        private static void WriteInteger(BinaryWriter writer, byte[] value)
        {
            writer.Write((byte)0x02); // INTEGER 標記

            // 移除前導的 0x00（如果有）
            int offset = 0;
            while (offset < value.Length && value[offset] == 0)
                offset++;
            byte[] trimmed = new byte[value.Length - offset];
            Array.Copy(value, offset, trimmed, 0, trimmed.Length);
            if (trimmed.Length == 0)
                trimmed = new byte[] { 0x00 };

            // 若第一個位元組大於 0x7F，則必須前置 0x00 以表正數
            if (trimmed[0] > 0x7F)
            {
                byte[] prefixed = new byte[trimmed.Length + 1];
                prefixed[0] = 0x00;
                Array.Copy(trimmed, 0, prefixed, 1, trimmed.Length);
                trimmed = prefixed;
            }
            byte[] lengthBytes = EncodeLength(trimmed.Length);
            writer.Write(lengthBytes);
            writer.Write(trimmed);
        }

        /// <summary>
        /// 根據長度產生 ASN.1 DER 編碼所需的長度位元組
        /// </summary>
        private static byte[] EncodeLength(int length)
        {
            if (length < 0x80)
            {
                return new byte[] { (byte)length };
            }
            else
            {
                List<byte> lengthBytes = new List<byte>();
                while (length > 0)
                {
                    lengthBytes.Insert(0, (byte)(length & 0xFF));
                    length >>= 8;
                }
                byte[] result = new byte[lengthBytes.Count + 1];
                result[0] = (byte)(0x80 | lengthBytes.Count);
                lengthBytes.CopyTo(result, 1);
                return result;
            }
        }


        /// <summary>
        /// 利用 RSAParameters 產生 PKCS#1 格式的 DER 編碼私鑰資料
        /// RSAPrivateKey ::= SEQUENCE {
        ///     version           Version,
        ///     modulus           INTEGER,  -- n
        ///     publicExponent    INTEGER,  -- e
        ///     privateExponent   INTEGER,  -- d
        ///     prime1            INTEGER,  -- p
        ///     prime2            INTEGER,  -- q
        ///     exponent1         INTEGER,  -- d mod (p-1)
        ///     exponent2         INTEGER,  -- d mod (q-1)
        ///     coefficient       INTEGER,  -- (inverse of q) mod p
        /// }
        /// </summary>
        public static byte[] ExportPrivateKeyToPkcs1(RSAParameters parameters)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)0x30); // SEQUENCE 標記
                using (var innerStream = new MemoryStream())
                using (var innerWriter = new BinaryWriter(innerStream))
                {
                    // version (0)
                    WriteInteger(innerWriter, new byte[] { 0x00 });
                    WriteInteger(innerWriter, parameters.Modulus);
                    WriteInteger(innerWriter, parameters.Exponent);
                    WriteInteger(innerWriter, parameters.D);
                    WriteInteger(innerWriter, parameters.P);
                    WriteInteger(innerWriter, parameters.Q);
                    WriteInteger(innerWriter, parameters.DP);
                    WriteInteger(innerWriter, parameters.DQ);
                    WriteInteger(innerWriter, parameters.InverseQ);
                    byte[] innerData = innerStream.ToArray();
                    byte[] lengthBytes = EncodeLength(innerData.Length);
                    writer.Write(lengthBytes);
                    writer.Write(innerData);
                }
                return stream.ToArray();
            }
        }


        /// <summary>
        /// 將 RSACryptoServiceProvider 物件中的私鑰轉換成 PEM 格式字串
        /// </summary>
        /// <param name="rsa">包含 RSA 金鑰對的物件</param>
        /// <returns>包含 PEM 標頭與結尾的私鑰字串</returns>
        public static string ExportPrivateKeyToPem(RSACryptoServiceProvider rsa)
        {
            RSAParameters parameters = rsa.ExportParameters(true);
            byte[] der = ExportPrivateKeyToPkcs1(parameters);
            string base64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
            return "-----BEGIN RSA PRIVATE KEY-----\n" + base64 + "\n-----END RSA PRIVATE KEY-----";
        }

        /// <summary>
        /// 將公鑰資訊 (模數與公開指數，以 Base64 字串表示) 轉換成 PEM 格式字串
        /// (採用 PKCS#1 格式)
        /// </summary>
        /// <param name="modulus">模數 n (Base64 字串)</param>
        /// <param name="exponent">公開指數 e (Base64 字串)</param>
        /// <returns>包含 PEM 標頭與結尾的公鑰字串</returns>
        public static string ConvertPublicKeyInfoToPem(string modulus, string exponent)
        {
            byte[] modBytes = Convert.FromBase64String(modulus);
            byte[] expBytes = Convert.FromBase64String(exponent);
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                // 建立 ASN.1 SEQUENCE
                writer.Write((byte)0x30);
                using (var innerStream = new MemoryStream())
                using (var innerWriter = new BinaryWriter(innerStream))
                {
                    WriteInteger(innerWriter, modBytes);
                    WriteInteger(innerWriter, expBytes);
                    byte[] innerData = innerStream.ToArray();
                    byte[] lengthBytes = EncodeLength(innerData.Length);
                    writer.Write(lengthBytes);
                    writer.Write(innerData);
                }
                byte[] der = stream.ToArray();
                string base64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
                return "-----BEGIN RSA PUBLIC KEY-----\n" + base64 + "\n-----END RSA PUBLIC KEY-----";
            }
        }

        /// <summary>
        /// 2. 輸入 payload 與私鑰，產生一組 JWT Token
        /// </summary>
        /// <param name="payload">要放入 JWT Payload 的字串資料</param>
        /// <param name="rsa">使用的 RSA 私鑰 (包含金鑰對)</param>
        /// <returns>JWT Token 字串</returns>
        public static string GenerateJwtToken(string payload, RSACryptoServiceProvider rsa)
        {
            // 建立基於 RSA 的安全金鑰
            var rsaKey = new RsaSecurityKey(rsa);

            // 以 RSA SHA-256 建立簽章憑證
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            // 將 payload 放入一個自訂的 claim (這邊使用 "data" 作為 key)
            var claims = new List<Claim>
            {
                new Claim("data", payload)
            };

            // 建立 JWT Token (您可以依需求設定 issuer、audience、有效時間等)
            var token = new JwtSecurityToken(
                issuer: "YourIssuer",         // 可自訂
                audience: "YourAudience",     // 可自訂
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: signingCredentials);

            // 將 JWT Token 轉換為字串
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// 3. 由私鑰導出公鑰資訊：模數 (n)、公開指數 (e) 與私鑰指數 (d)
        /// </summary>
        /// <param name="rsa">含有 RSA 金鑰對的物件</param>
        /// <param name="modulus">輸出：模數 n (以 Base64 字串表示)</param>
        /// <param name="exponent">輸出：公開指數 e (以 Base64 字串表示)</param>
        /// <param name="privateExponent">輸出：私鑰指數 d (以 Base64 字串表示)</param>
        public static void GetPublicKeyInfo(RSACryptoServiceProvider rsa, out string modulus, out string exponent, out string privateExponent)
        {
            // 匯出金鑰參數 (true 表示包含私鑰參數)
            RSAParameters parameters = rsa.ExportParameters(true);

            modulus = Convert.ToBase64String(parameters.Modulus);
            exponent = Convert.ToBase64String(parameters.Exponent);
            privateExponent = Convert.ToBase64String(parameters.D);
        }

        /// <summary>
        /// 4. 驗證 JWT
        /// 輸入 JWT Token 字串與公鑰資訊 (模數與公開指數)，驗證該 JWT 的簽章是否正確，
        /// 若驗證通過則回傳驗證後的 ClaimsPrincipal。
        /// </summary>
        /// <param name="token">JWT Token 字串</param>
        /// <param name="modulus">公鑰資訊的模數 (Base64 字串)</param>
        /// <param name="exponent">公鑰資訊的公開指數 (Base64 字串)</param>
        /// <returns>驗證通過後的 ClaimsPrincipal，驗證失敗時則丟出例外</returns>
        public static ClaimsPrincipal ValidateJwtToken(string token, string modulus, string exponent)
        {
            // 由 Base64 字串還原 RSAParameters
            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = Convert.FromBase64String(modulus),
                Exponent = Convert.FromBase64String(exponent)
            };

            // 利用公鑰資訊建立 RSA 物件
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParameters);
                var rsaKey = new RsaSecurityKey(rsa);

                // 設定 JWT Token 的驗證參數
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = rsaKey,
                    // 以下驗證參數可依需求調整
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                SecurityToken validatedToken;
                // 驗證 JWT，若驗證失敗會丟出例外
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
                return principal;
            }
        }



        /// <summary>
        /// 輸入一個 PEM 格式的私鑰字串，轉換回 RSACryptoServiceProvider 物件
        /// </summary>
        /// <param name="pem">
        /// PEM 格式私鑰字串，必須包含 "-----BEGIN RSA PRIVATE KEY-----" 與 "-----END RSA PRIVATE KEY-----" 標記
        /// </param>
        /// <returns>RSACryptoServiceProvider 物件</returns>
        public static RSACryptoServiceProvider LoadPrivateKeyFromPem(string pem)
        {
            // 移除標頭、結尾以及換行符號
            string header = "-----BEGIN RSA PRIVATE KEY-----";
            string footer = "-----END RSA PRIVATE KEY-----";
            string key = pem.Replace(header, "")
                            .Replace(footer, "")
                            .Replace("\r", "")
                            .Replace("\n", "")
                            .Trim();

            byte[] keyBytes = Convert.FromBase64String(key);
            return DecodeRsaPrivateKey(keyBytes);
        }

        /// <summary>
        /// 從 DER 編碼的 PKCS#1 格式私鑰資料轉換成 RSACryptoServiceProvider 物件
        /// </summary>
        private static RSACryptoServiceProvider DecodeRsaPrivateKey(byte[] keyBytes)
        {
            using (var ms = new MemoryStream(keyBytes))
            using (var reader = new BinaryReader(ms))
            {
                // 檢查 SEQUENCE 標記
                byte bt = reader.ReadByte();
                if (bt != 0x30)
                    throw new Exception("Invalid PEM format: expected SEQUENCE");

                // 讀取整個 SEQUENCE 的長度（但此值本身可忽略）
                int seqLength = ReadLength(reader);

                // 讀取 version
                bt = reader.ReadByte();
                if (bt != 0x02)
                    throw new Exception("Invalid PEM format: expected INTEGER for version");
                int versionLength = ReadLength(reader);
                byte[] version = reader.ReadBytes(versionLength);

                // 依序讀取 RSA 私鑰的各個 INTEGER 成員
                RSAParameters parameters = new RSAParameters();
                parameters.Modulus = ReadInteger(reader);
                parameters.Exponent = ReadInteger(reader);
                parameters.D = ReadInteger(reader);
                parameters.P = ReadInteger(reader);
                parameters.Q = ReadInteger(reader);
                parameters.DP = ReadInteger(reader);
                parameters.DQ = ReadInteger(reader);
                parameters.InverseQ = ReadInteger(reader);

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(parameters);
                return rsa;
            }
        }


        /// <summary>
        /// 讀取 DER 格式中編碼的長度
        /// </summary>
        private static int ReadLength(BinaryReader reader)
        {
            int length = reader.ReadByte();
            if ((length & 0x80) != 0)
            {
                int byteCount = length & 0x7F;
                byte[] lengthBytes = reader.ReadBytes(byteCount);
                int result = 0;
                for (int i = 0; i < lengthBytes.Length; i++)
                {
                    result = (result << 8) + lengthBytes[i];
                }
                return result;
            }
            return length;
        }

        /// <summary>
        /// 讀取 DER 格式中編碼的 INTEGER 整數
        /// </summary>
        private static byte[] ReadInteger(BinaryReader reader)
        {
            if (reader.ReadByte() != 0x02)
                throw new Exception("Expected INTEGER tag");
            int length = ReadLength(reader);
            byte[] integerBytes = reader.ReadBytes(length);
            // 若有前導零，則移除之
            if (integerBytes[0] == 0x00)
            {
                byte[] tmp = new byte[integerBytes.Length - 1];
                Array.Copy(integerBytes, 1, tmp, 0, tmp.Length);
                return tmp;
            }
            return integerBytes;
        }
    }
}
