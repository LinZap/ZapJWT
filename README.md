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
MIIEpAIBAAKCAQEAwf4nSTxREfGvhm4RDv4FdjlpdlC0C9zNK6sRxXPPZVomh/TrIs/0+OkIqieQ
kVoQs2NGl5SDuslHN49Kt8cCi3KQ8e/s1rH+BC8YXPEOfOHJK3re8psWdWhUe4h1hrPUtqlhQgl7
KugT7B72CWX0ZNkLb1hB4BbwaG3WAE7XqU1m/JuR3/Z59rZtbsv7uRe2/DcoyIZzJde6J8aduStb
1Tr47jS1XZFPlT3LCuLqoLFbwxIi5ykr+F0ciQOLHA3YceQ8orAfQlDJkUPKIocsFaFsAXuEoSHI
Bgm+JuYcX4itbcD3zw220DQmHa3OCQqDv6ADE1UNV5xbJ6XVoUYP7QIDAQABAoIBADl4KH1KsB2n
wr8JZmZRnJ6cfYC+gcgt3l48bKRZHazB2z5VsT776m++4YE+/VYCH4Z1N5l6Ntgj/sQX4CO3gip7
gzMZR8mGq2Dj7szB4O/gF6+Y0+l9Rlb71GNQVrjUF4URgq2Ej4dzf0tpFKxOFuu1XOzccY+IXCoj
t80ZjkwqC8tehzgrMSuJOUSz120/ZloqUZ/fL8WSbfCssvley+2+XUi1YHjXDI89759NXfHvQVBS
gI3D1R7ndPlPPXcSvdhJhBSzGxcZy3h24CjWAWnV9tOZ0vIW3DCJmcQejdllmkEf0sm3/z2xy5zC
GweS2Nr3Zn33fCibEFuq6+djcQUCgYEA/rYUour2VU5OkBK770VfF1fOBGpyfCDaqA3mKekVxrhy
0eo0eKMtu3UeaKyMF0eA4bWJS/u4ZbRcSPRk0ObX+HCyLjSWrJ8HpiAY8jadkOLymjljZNO4TBed
77Xe4IfbA3x7+S2GM9Eucm2RuorA9ijHTLV1HttSxg3dIxaZgwMCgYEAwvltGExS6x590kjc5lFf
8SYOgadXElEo2oWl6aA/6vGv6rCvYVeEEBfqIQsjPWxYc9W1csVa7WQaTYZZrUuBNLWIBawEU722
GO39294rvglhXwhJZ7R+YTY/DNpgrDLFtLgAyUmprSRFdryFZ/prQAHU72qSpg4rvmN8/atsNk8C
gYEAvh0BgiiF/F4aXYbeJ1VMCIxNBRa+pM+Q5Oaa6KVEz7JUYUHCMFj7hXOBYveHCMkh9VYeSEx1
8dORHhLsPNBQWusi00IFRIrelqxWclM5gC8kjOBQw60TXhgylfzVghlk61E6512HUZ3MYTRPFUED
jbgaKbM22/Uv7wviBpKTuikCgYEAoQqJ7H7mIiOeQzlBk8700ubfJoIEbjGw78ViA7UD9lfIOK3V
Pi6d+vj1vnNHmS1LZenHpFOURe3ft9bXbUanItUp052AOXbB2JeCjb9VG/L9hRQAJXM0y7CVpVUe
cjzBhgJRS/DXABasdWVDP13chhK9QT8if5vGz8u26oNTrwsCgYBWN4RxX/gQzhkeUZ7XkFUazM7N
Z8z+7F1FZ8pZ07zBfLXOhQ8EAjLe1isIrauHmwEVkXpp/y2C0PA3BbRiE5NABMtnWX73sEkM/5uE
G+8z+7fZr3RFQsDH6qBGcGIOQIcr+SLBcen5ZYWFDpS47W0SfgaeXc1SYRxGharUaz4daQ==
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
模數 (n): wf4nSTxREfGvhm4RDv4FdjlpdlC0C9zNK6sRxXPPZVomh/TrIs/0+OkIqieQkVoQs2NGl5SDuslHN49Kt8cCi3KQ8e/s1rH+BC8YXPEOfOHJK3re8psWdWhUe4h1hrPUtqlhQgl7KugT7B72CWX0ZNkLb1hB4BbwaG3WAE7XqU1m/JuR3/Z59rZtbsv7uRe2/DcoyIZzJde6J8aduStb1Tr47jS1XZFPlT3LCuLqoLFbwxIi5ykr+F0ciQOLHA3YceQ8orAfQlDJkUPKIocsFaFsAXuEoSHIBgm+JuYcX4itbcD3zw220DQmHa3OCQqDv6ADE1UNV5xbJ6XVoUYP7Q==
公開指數 (e): AQAB
私鑰指數 (d): OXgofUqwHafCvwlmZlGcnpx9gL6ByC3eXjxspFkdrMHbPlWxPvvqb77hgT79VgIfhnU3mXo22CP+xBfgI7eCKnuDMxlHyYarYOPuzMHg7+AXr5jT6X1GVvvUY1BWuNQXhRGCrYSPh3N/S2kUrE4W67Vc7Nxxj4hcKiO3zRmOTCoLy16HOCsxK4k5RLPXbT9mWipRn98vxZJt8Kyy+V7L7b5dSLVgeNcMjz3vn01d8e9BUFKAjcPVHud0+U89dxK92EmEFLMbFxnLeHbgKNYBadX205nS8hbcMImZxB6N2WWaQR/Sybf/PbHLnMIbB5LY2vdmffd8KJsQW6rr52NxBQ==
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
MIIBCgKCAQEAwf4nSTxREfGvhm4RDv4FdjlpdlC0C9zNK6sRxXPPZVomh/TrIs/0+OkIqieQkVoQ
s2NGl5SDuslHN49Kt8cCi3KQ8e/s1rH+BC8YXPEOfOHJK3re8psWdWhUe4h1hrPUtqlhQgl7KugT
7B72CWX0ZNkLb1hB4BbwaG3WAE7XqU1m/JuR3/Z59rZtbsv7uRe2/DcoyIZzJde6J8aduStb1Tr4
7jS1XZFPlT3LCuLqoLFbwxIi5ykr+F0ciQOLHA3YceQ8orAfQlDJkUPKIocsFaFsAXuEoSHIBgm+
JuYcX4itbcD3zw220DQmHa3OCQqDv6ADE1UNV5xbJ6XVoUYP7QIDAQAB
-----END RSA PUBLIC KEY-----
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
nbf: 1739320525
exp: 1739324125
iss: YourIssuer
aud: YourAudience
```


# 參考資料


請參考 ChatGPT 最新模型生成結果 [C# JWT 生成工作](https://chatgpt.com/share/67abec1e-f08c-800e-99d0-ec2256cec4ec)