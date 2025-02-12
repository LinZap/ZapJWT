using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapJWT
{
    public class Program
    {
        static void Main(string[] args)
        {
            // 產生 RSA 私鑰 (包含公鑰資訊)
            var rsa = JwtGenerator.GeneratePrivateKey();

            // 轉換私鑰為 PEM 格式字串
            string pemPrivateKey = JwtGenerator.ExportPrivateKeyToPem(rsa);
            Console.WriteLine("\nPEM 格式私鑰：\n" + pemPrivateKey);


            // 使用自訂 payload 產生 JWT Token
            string payload = "這是測試用的 payload 資料";
            string jwtToken = JwtGenerator.GenerateJwtToken(payload, rsa);
            Console.WriteLine("JWT Token:");
            Console.WriteLine(jwtToken);




            // 從私鑰中取得公鑰資訊 (模數 n、公開指數 e、私鑰指數 d)
            JwtGenerator.GetPublicKeyInfo(rsa, out string modulus, out string exponent, out string privateExponent);
            Console.WriteLine("\n金鑰資訊：");
            Console.WriteLine("模數 (n): " + modulus);
            Console.WriteLine("公開指數 (e): " + exponent);
            Console.WriteLine("私鑰指數 (d): " + privateExponent);


            // 轉換公鑰為 PEM 格式字串
            string pemPublicKey = JwtGenerator.ConvertPublicKeyInfoToPem(modulus, exponent);
            Console.WriteLine("\nPEM 格式公鑰：\n" + pemPublicKey);


            // 驗證 JWT Token
            try
            {
                var principal = JwtGenerator.ValidateJwtToken(jwtToken, modulus, exponent);
                Console.WriteLine("\nJWT 驗證成功！");
                Console.WriteLine("取得的 Claims：");
                foreach (var claim in principal.Claims)
                {
                    Console.WriteLine($"{claim.Type}: {claim.Value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nJWT 驗證失敗！");
                Console.WriteLine("錯誤訊息：" + ex.Message);
            }

            Console.WriteLine("\n按任一鍵退出...");
            Console.ReadKey();
        }
    }


}
