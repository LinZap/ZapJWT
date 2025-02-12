# Zap JWT Side Project

Zap 撰寫的小型 JWT 產生與驗證小工具，目的是用於自己建立 JWT 並使用 RSA256 演算法來進行加密資料

# 使用說明

以下展示幾個範例，詳情可以直接開啟 `Program.cs` 直接執行，即可得到以下全部結果 


## 私鑰產生

生成一組私鑰

```csharp
// 產生 RSA 私鑰 (包含公鑰資訊)
var rsa = JwtGenerator.GeneratePrivateKey();

// 轉換私鑰為 PEM 格式字串
string pemPrivateKey = JwtGenerator.ExportPrivateKeyToPem(rsa);
Console.WriteLine("\nPEM 格式私鑰：\n" + pemPrivateKey);
```

**輸出:**

```
PEM 格式私鑰：
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsgx6r+BrA4QXNzvcMr6JpfJdf8bgi32KiUkMci+y8GPZeiHxDQ7NpeuoYfU7
W//mLRQajGT+lN+Jh3sXo1auCMAS0UVQUjziDwKwFy48/lXqqip7VO5BtD1W/PSv2J3AGCwzsTck
AadATpQ6JRDsJSLkLS7U0WfxjKSfodw/0jWz+oXEvcFlE6HhpnEW7WjR8321M05w953RFKZWUhxF
Yn+EqcSSPRtMrzlSEW0u8ISRphU1fcZMg19G8JaRzo0LPML6BzVj5TnPLeAkMSw273caSYHlf3ZI
kfiHCbzrcxRGrHU1K96iYkeOjfag5VV2KpSHLBZyoNJJV9vv92mHCQIDAQABAoIBAEoTSw/VLHCg
ChCexPQPtbDm7uN0WINwTazkSVtQYQAGarqXWHR4TjLTopBuuK2D/72NeaYjdo91mQBWw/Te4TUe
xDVwwwQT9HEOSzi5sgKWuDTny7wADDHyuzgujOJwbzUfXrpCGKbfcK/Al5hIPBcPNyNdMomU1zgO
XaO3wI2xu/vK/qVJkrhZD133GcuAhfUvC4bhetpYHMK6vmIjrS3ZEePP5uYVS/sz32p+HAC7kb4+
D8GyVaSV9ZpxQBDPrrJPScYa128zGNrJQpb5NvXzqpVfpbW8Rl1LV9aTWcXi75A9FANI0+Ut1m9X
dEwDVHDAW7w/uO0z8F5HFGW5GykCgYEAxo+OD1vY7aTLinU65zd4EybsvtdSSglRDwnAJBY18BGf
m+Zqinpz8T/BDyi0Len1LB3zn9Xw+w1quqVoNlb8CUKZEkjQn3sXeo/jlxaYYdDLVjf+5IixvZb/
RYSiYbnieiQFWygm+iuhQ0RkV3wfRYmAa+FquwOohHl+58GeRq8CgYEA5Y3nevFZ1DwB463pZ9BI
bLktkFus0VLiY6NJe9EIpaI8uy5Br/k4fdAte1CM7W6rUKI3MrKvoxR2u9+OehflIzupUB4K9OFQ
F4iUHS9ZBUFsT2Qh8vYcVDWGrlH6l+hu6FnS8MnuAhqBATJ+jfSfb6qEMA3t3Gj4l/MeRQ/d+8cC
gYEAsUbZ/rxyITpQv32K6YSMoAzQslJsFc3boSGDerSZ04zog7hkxt4tRec15uLge122l3zmVn4c
eQixkZK8SEfBHkNnhvubx8eOXs6409xIkIxp/sBfwoqIpkx5/Qc+MyJTIdmnLovawODTSct2CuW2
xc7N6YOIVxAdFKmktCYZueECgYBHUHaBc0l87ceIfBbu8X4OiNjm6BQgU6eRXMEPfjk5e9VyMUSm
7r3mGC6JCNU/Tgpa2opbbbey6kCYzTLuK048S+Slxy+QNA81wHCDQJpfT5vebjU9zcevQZG9xiob
11HdTUqDE7ilXqaFQLKgV0bQ4iB+7VTgDJxuWFEnE27bMQKBgGkDKweODeejLLDIvNtMvq6NutoO
mNTbzyQP5ib9OacuP2XSzWg5ugWTwGT+/Su1MI5AyKdzaKfLXMmYTg1UrDZXSK0Tgv01Nws3YfpP
R7lltdZoDY41RMZ8+vvcDRQ3jhYnqIjE1cZ8+641dC/daJgc6KOujT307Z98e3DnL3E3
-----END RSA PRIVATE KEY-----
```


## 基於私鑰產生公鑰資訊

根據私鑰產生公鑰資訊: 模數 (n), 公開指數 (e), 私鑰指數 (d)

```csharp
// 從私鑰中取得公鑰資訊 (模數 n、公開指數 e、私鑰指數 d)
JwtGenerator.GetPublicKeyInfo(rsa, out string modulus, out string exponent, out string privateExponent);
Console.WriteLine("\n金鑰資訊：");
Console.WriteLine("模數 (n): " + modulus);
Console.WriteLine("公開指數 (e): " + exponent);
Console.WriteLine("私鑰指數 (d): " + privateExponent);
```


**輸出:**

```
金鑰資訊：
模數 (n): sgx6r+BrA4QXNzvcMr6JpfJdf8bgi32KiUkMci+y8GPZeiHxDQ7NpeuoYfU7W//mLRQajGT+lN+Jh3sXo1auCMAS0UVQUjziDwKwFy48/lXqqip7VO5BtD1W/PSv2J3AGCwzsTckAadATpQ6JRDsJSLkLS7U0WfxjKSfodw/0jWz+oXEvcFlE6HhpnEW7WjR8321M05w953RFKZWUhxFYn+EqcSSPRtMrzlSEW0u8ISRphU1fcZMg19G8JaRzo0LPML6BzVj5TnPLeAkMSw273caSYHlf3ZIkfiHCbzrcxRGrHU1K96iYkeOjfag5VV2KpSHLBZyoNJJV9vv92mHCQ==
公開指數 (e): AQAB
私鑰指數 (d): ShNLD9UscKAKEJ7E9A+1sObu43RYg3BNrORJW1BhAAZqupdYdHhOMtOikG64rYP/vY15piN2j3WZAFbD9N7hNR7ENXDDBBP0cQ5LOLmyApa4NOfLvAAMMfK7OC6M4nBvNR9eukIYpt9wr8CXmEg8Fw83I10yiZTXOA5do7fAjbG7+8r+pUmSuFkPXfcZy4CF9S8LhuF62lgcwrq+YiOtLdkR48/m5hVL+zPfan4cALuRvj4PwbJVpJX1mnFAEM+usk9JxhrXbzMY2slClvk29fOqlV+ltbxGXUtX1pNZxeLvkD0UA0jT5S3Wb1d0TANUcMBbvD+47TPwXkcUZbkbKQ==
```


## 基於公鑰資訊產生公鑰

輸入公鑰資訊產生公鑰字串

```csharp
// 轉換公鑰為 PEM 格式字串
string pemPublicKey = JwtGenerator.ConvertPublicKeyInfoToPem(modulus, exponent);
Console.WriteLine("\nPEM 格式公鑰：\n" + pemPublicKey);
```

**輸出:**

```
PEM 格式公鑰：
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsgx6r+BrA4QXNzvcMr6JpfJdf8bgi32KiUkMci+y8GPZeiHxDQ7NpeuoYfU7W//m
LRQajGT+lN+Jh3sXo1auCMAS0UVQUjziDwKwFy48/lXqqip7VO5BtD1W/PSv2J3AGCwzsTckAadA
TpQ6JRDsJSLkLS7U0WfxjKSfodw/0jWz+oXEvcFlE6HhpnEW7WjR8321M05w953RFKZWUhxFYn+E
qcSSPRtMrzlSEW0u8ISRphU1fcZMg19G8JaRzo0LPML6BzVj5TnPLeAkMSw273caSYHlf3ZIkfiH
CbzrcxRGrHU1K96iYkeOjfag5VV2KpSHLBZyoNJJV9vv92mHCQIDAQAB
-----END RSA PUBLIC KEY-----
```

## 產生 JWT

輸入一組 payload 資料字串與私鑰，算出一組 JWT

```csharp
// 使用自訂 payload 產生 JWT Token
string payload = "這是測試用的 payload 資料";
string jwtToken = JwtGenerator.GenerateJwtToken(payload, rsa);
Console.WriteLine("JWT Token:");
Console.WriteLine(jwtToken);
```

**輸出:**

```
JWT Token:
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoi6YCZ5piv5ris6Kmm55So55qEIHBheWxvYWQg6LOH5paZIiwibmJmIjoxNzM5MzIyMDM4LCJleHAiOjE3MzkzMjU2MzgsImlzcyI6IllvdXJJc3N1ZXIiLCJhdWQiOiJZb3VyQXVkaWVuY2UifQ.Eri1ETLQMMP1b4BA23dytuBU1CFZJ7S0TcR5KGsGT-nYTfoCvWzGM79iwKmpzUavV5xIzEv6Xw3qvN88FERb69XNE24vmrrllcfLd05QMSjBD7j35uXJm-26J-YjUVAMca5Pz-nXcp9YXBIZL6LyzQzQrBHXwBYvj3ZT1o_EBbyyI3Auf3p3psisiRrrkqMf4Udua-dob3468RuXaWstw_rN2YGvoFQy4FOQmc5r6YOct6j1ET3_EwKHimx2LIq3LvA3SXY9UoiWQh4oTKILe0Cx8gB4C6Pi94W5g2eeuKVII1CQVA3NaXP1SgJ4_Hu7_KCAdZT9q5N4nNxdm9iC6w
```

## 驗證 JWT

輸入一組 JWT 與公鑰資訊，驗證該 JWT 是否合法

```csharp
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
```


**輸出:**

```
JWT 驗證成功！
取得的 Claims：
data: 這是測試用的 payload 資料
nbf: 1739322038
exp: 1739325638
iss: YourIssuer
aud: YourAudience
```


# 參考資料


請參考 ChatGPT 最新模型生成結果 [C# JWT 生成工作](https://chatgpt.com/share/67abec1e-f08c-800e-99d0-ec2256cec4ec)