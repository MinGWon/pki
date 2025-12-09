# 2Check Agent 개발 명세서 (C#)

## 프로젝트 개요

- **프로젝트명**: TwoCheckAgent
- **플랫폼**: Windows Forms App (.NET 8.0)
- **역할**: 사용자 PC에서 인증서 저장/로드/서명 처리
- **통신**: localhost:52080 HTTP 서버

---

## 1. 프로젝트 구조

```
TwoCheckAgent/
├── TwoCheckAgent.csproj
├── Program.cs
├── MainForm.cs                 # 시스템 트레이 폼
├── Services/
│   ├── HttpServerService.cs    # Kestrel HTTP 서버
│   ├── CertificateService.cs   # 인증서 관리
│   └── SigningService.cs       # 서명 처리
├── Models/
│   ├── CertificateInfo.cs
│   └── SignRequest.cs
├── Controllers/
│   ├── HealthController.cs
│   └── CertificatesController.cs
└── appsettings.json
```

---

## 2. NuGet 패키지

```xml
<ItemGroup>
  <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="8.0.0" />
  <PackageReference Include="System.Security.Cryptography.Pkcs" Version="8.0.0" />
</ItemGroup>

<ItemGroup>
  <FrameworkReference Include="Microsoft.AspNetCore.App" />
</ItemGroup>
```

---

## 3. HTTP API 명세

### 3.1 GET /api/health
```json
Response 200:
{
  "status": "ok",
  "version": "1.0.0"
}
```

### 3.2 GET /api/certificates
```json
Response 200:
[
  {
    "certId": "uuid",
    "serialNumber": "ABC123",
    "subjectDN": "CN=홍길동, O=2Check, C=KR",
    "issuerDN": "CN=2Check Intermediate CA",
    "notBefore": "2024-01-01T00:00:00Z",
    "notAfter": "2025-01-01T00:00:00Z",
    "isExpired": false
  }
]
```

### 3.3 POST /api/certificates (저장)
```json
Request:
{
  "p12Data": "MIIxxxxBase64EncodedP12xxxx",
  "drive": "C",
  "metadata": {
    "serialNumber": "ABC123",
    "subjectDN": "CN=홍길동, O=2Check, C=KR",
    "issuerDN": "CN=2Check Intermediate CA, O=2Check, C=KR",
    "notAfter": "2025-01-01T00:00:00Z",
    "displayName": "홍길동"  // 표시용 이름 (원본 한글)
  }
}
// ⚠️ 비밀번호 전달 안함! P12는 이미 암호화되어 있음

Response 201:
{
  "success": true,
  "certId": "uuid",
  "path": "C:\\2check\\cert\\uuid\\cert.p12"
}
```

### 3.4 DELETE /api/certificates/{id}
```json
Response 200:
{
  "success": true
}
```

### 3.5 POST /api/certificates/{id}/sign (서명)
```json
Request:
{
  "data": "c2lnbmF0dXJlLWRhdGE=",  // Base64 서명할 데이터
  "password": "인증서비밀번호"       // 서명할 때만 비밀번호 필요!
}
// ⚠️ 비밀번호는 서명 시에만 전달, 사용 후 즉시 메모리에서 폐기

Response 200:
{
  "signature": "xxxxxxBase64Signaturexxxxxx",
  "serialNumber": "ABC123"
}
```

### 추가 API: 드라이브 목록 조회

### GET /api/drives
```json
Response 200:
[
  {
    "letter": "C",
    "label": "로컬 디스크",
    "type": "fixed",
    "freeSpace": "128.5 GB"
  },
  {
    "letter": "D",
    "label": "USB 드라이브",
    "type": "removable",
    "freeSpace": "14.2 GB"
  }
]
```

---

## 4. 핵심 코드 예시

### 4.1 Program.cs
```csharp
using TwoCheckAgent;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://localhost:52080");

builder.Services.AddControllers();
builder.Services.AddSingleton<CertificateService>();

var app = builder.Build();

// CORS 설정
app.UseCors(policy => policy
    .WithOrigins("https://pki.2check.io", "http://localhost:3000")
    .AllowAnyMethod()
    .AllowAnyHeader());

app.MapControllers();

// Windows Forms 시스템 트레이와 함께 실행
Application.EnableVisualStyles();
Application.SetCompatibleTextRenderingDefault(false);

var mainForm = new MainForm();
_ = Task.Run(() => app.Run());

Application.Run(mainForm);
```

### 4.2 CertificateService.cs
```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class CertificateService
{
    private readonly string _certPath = @"C:\2check\cert";

    public CertificateService()
    {
        Directory.CreateDirectory(_certPath);
    }

    public List<CertificateInfo> GetCertificates()
    {
        var result = new List<CertificateInfo>();
        
        foreach (var dir in Directory.GetDirectories(_certPath))
        {
            var metaFile = Path.Combine(dir, "metadata.json");
            if (File.Exists(metaFile))
            {
                var json = File.ReadAllText(metaFile);
                var info = JsonSerializer.Deserialize<CertificateInfo>(json);
                if (info != null) result.Add(info);
            }
        }
        
        return result;
    }

    public string SaveCertificate(byte[] p12Data, string password)
    {
        var cert = new X509Certificate2(p12Data, password, 
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        
        var certId = Guid.NewGuid().ToString();
        var certDir = Path.Combine(_certPath, certId);
        Directory.CreateDirectory(certDir);
        
        // P12 파일 저장
        File.WriteAllBytes(Path.Combine(certDir, "cert.p12"), p12Data);
        
        // 메타데이터 저장
        var metadata = new CertificateInfo
        {
            CertId = certId,
            SerialNumber = cert.SerialNumber,
            SubjectDN = cert.Subject,
            IssuerDN = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            IsExpired = DateTime.Now > cert.NotAfter
        };
        
        File.WriteAllText(
            Path.Combine(certDir, "metadata.json"),
            JsonSerializer.Serialize(metadata));
        
        return certId;
    }

    public byte[] Sign(string certId, byte[] data, string password)
    {
        var certDir = Path.Combine(_certPath, certId);
        var p12Path = Path.Combine(certDir, "cert.p12");
        
        var p12Data = File.ReadAllBytes(p12Path);
        using var cert = new X509Certificate2(p12Data, password);
        
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa == null) throw new Exception("No private key");
        
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

### 4.3 CertificatesController.cs
```csharp
[ApiController]
[Route("api/certificates")]
public class CertificatesController : ControllerBase
{
    private readonly CertificateService _certService;

    public CertificatesController(CertificateService certService)
    {
        _certService = certService;
    }

    [HttpGet]
    public IActionResult GetCertificates()
    {
        return Ok(_certService.GetCertificates());
    }

    [HttpPost]
    public IActionResult ImportCertificate([FromBody] ImportRequest request)
    {
        try
        {
            var p12Data = Convert.FromBase64String(request.P12Data);
            var certId = _certService.SaveCertificate(p12Data, request.Password);
            return Created($"/api/certificates/{certId}", new { success = true, certId });
        }
        catch
        {
            return BadRequest(new { error = "Invalid certificate or password" });
        }
    }

    [HttpPost("{id}/sign")]
    public IActionResult Sign(string id, [FromBody] SignRequest request)
    {
        try
        {
            var data = Convert.FromBase64String(request.Data);
            var signature = _certService.Sign(id, data, request.Password);
            var cert = _certService.GetCertificates().First(c => c.CertId == id);
            
            return Ok(new
            {
                signature = Convert.ToBase64String(signature),
                serialNumber = cert.SerialNumber
            });
        }
        catch (CryptographicException)
        {
            return Unauthorized(new { error = "Invalid password" });
        }
    }
}
```

### 4.4 MainForm.cs (시스템 트레이)
```csharp
public class MainForm : Form
{
    private NotifyIcon _trayIcon;
    private ContextMenuStrip _trayMenu;

    public MainForm()
    {
        this.WindowState = FormWindowState.Minimized;
        this.ShowInTaskbar = false;
        this.FormBorderStyle = FormBorderStyle.None;
        this.Load += (s, e) => this.Hide();

        _trayMenu = new ContextMenuStrip();
        _trayMenu.Items.Add("인증서 등록", null, OnImportCert);
        _trayMenu.Items.Add("인증서 목록", null, OnShowCerts);
        _trayMenu.Items.Add("-");
        _trayMenu.Items.Add("종료", null, OnExit);

        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            ContextMenuStrip = _trayMenu,
            Text = "2Check Agent",
            Visible = true
        };
    }

    private void OnImportCert(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "PKCS#12 파일|*.p12;*.pfx",
            Title = "인증서 파일 선택"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            var password = Microsoft.VisualBasic.Interaction.InputBox(
                "인증서 비밀번호를 입력하세요:", "비밀번호 입력");
            
            if (!string.IsNullOrEmpty(password))
            {
                // 인증서 등록 로직
            }
        }
    }

    private void OnShowCerts(object? sender, EventArgs e)
    {
        // 인증서 목록 창 표시
    }

    private void OnExit(object? sender, EventArgs e)
    {
        _trayIcon.Visible = false;
        Application.Exit();
    }
}
```

---

## 5. 보안 고려사항

1. **localhost만 바인딩**: `UseUrls("http://localhost:52080")`
2. **Origin 검증**: CORS로 허용된 도메인만 접근
3. **비밀번호 메모리 관리**: 사용 후 즉시 폐기
4. **Rate Limiting**: 분당 요청 수 제한

---

## 6. 빌드 및 배포

```bash
# 빌드
dotnet publish -c Release -r win-x64 --self-contained

# 설치 프로그램 (Inno Setup 사용 권장)
```

---

## 7. Base64 인코딩 주의사항 (중요!)

### 서명 시 Base64 처리

```csharp
// 요청 데이터 디코딩 (URL-safe Base64 처리)
public static byte[] DecodeBase64(string base64)
{
    // URL-safe 문자를 표준 Base64로 변환
    string standard = base64
        .Replace('-', '+')
        .Replace('_', '/');
    
    // 패딩 추가
    switch (standard.Length % 4)
    {
        case 2: standard += "=="; break;
        case 3: standard += "="; break;
    }
    
    return Convert.FromBase64String(standard);
}

// 서명 결과를 표준 Base64로 인코딩
public static string EncodeBase64(byte[] data)
{
    return Convert.ToBase64String(data);  // 표준 Base64 사용
}
```

### POST /api/certificates/{id}/sign 응답

```json
{
  "signature": "표준 Base64 문자열 (+, /, = 포함)",
  "serialNumber": "ABC123"
}
```

⚠️ **중요**: 
- 요청의 `data` 필드는 URL-safe Base64일 수 있으므로 변환 필요
- 응답의 `signature`는 표준 Base64로 반환 (서버에서 처리 가능)

---

## 8. 보안 Q&A

### Q: metadata.json을 위조하면 어떻게 되나요?

**A: 위조해도 인증에 실패합니다.**

#### 이유:
1. **서명은 cert.p12 안의 개인키로 수행됨**
   - metadata.json의 serialNumber를 바꿔도 실제 서명에 사용되는 키는 변하지 않음

2. **서버는 DB 기준으로 검증함**
   - 서버는 Agent가 보낸 `serialNumber`로 DB에서 공개키 조회
   - 위조된 serialNumber → 다른 사람의 공개키 조회 → 서명 불일치 → 인증 실패

3. **cert.p12는 암호화되어 있음**
   - P12 파일 자체를 조작하려면 비밀번호 필요
   - 비밀번호 없이는 개인키 추출 불가

#### 공격 시나리오 분석:

| 시나리오 | 결과 |
|---------|------|
| metadata.json의 serialNumber 변경 | ❌ 서명 검증 실패 |
| 다른 사람의 cert.p12 복사 | ❌ 비밀번호 모름 → 서명 불가 |
| cert.p12와 metadata.json 모두 복사 | ❌ 비밀번호 모름 → 서명 불가 |
| 비밀번호까지 알아냄 | ⚠️ 이건 인증서 유출 (별도 대응 필요) |

#### 결론:
- **metadata.json은 편의를 위한 캐시일 뿐**
- **실제 보안은 cert.p12 + 비밀번호 + 서버 검증에 의존**

---

### Q: 그래도 metadata.json 무결성을 검증하고 싶다면?

Agent에서 메타데이터 저장 시 서명을 추가할 수 있습니다:

```csharp
// 저장 시
public void SaveCertificateWithIntegrity(byte[] p12Data, CertificateInfo metadata)
{
    // 메타데이터를 JSON으로 직렬화
    var json = JsonSerializer.Serialize(metadata);
    
    // P12에서 개인키로 메타데이터 서명
    using var cert = new X509Certificate2(p12Data, password);
    using var rsa = cert.GetRSAPrivateKey();
    var signature = rsa.SignData(
        Encoding.UTF8.GetBytes(json), 
        HashAlgorithmName.SHA256, 
        RSASignaturePadding.Pkcs1
    );
    
    // 저장
    File.WriteAllText("metadata.json", json);
    File.WriteAllBytes("metadata.sig", signature);
}

// 로드 시 검증
public bool VerifyMetadataIntegrity(string certId, string password)
{
    var json = File.ReadAllText("metadata.json");
    var signature = File.ReadAllBytes("metadata.sig");
    var p12Data = File.ReadAllBytes("cert.p12");
    
    using var cert = new X509Certificate2(p12Data, password);
    using var rsa = cert.GetRSAPublicKey();
    
    return rsa.VerifyData(
        Encoding.UTF8.GetBytes(json),
        signature,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1
    );
}
```

하지만 **이것도 비밀번호 없이는 검증 불가**하므로, 실질적인 보안 향상은 제한적입니다.

---

## 9. serialNumber 보호 (권장)

### 문제점
- metadata.json에 serialNumber가 평문으로 저장됨
- 파일 유출 시 인증서 식별 정보 노출

### 해결책: 해시 기반 식별

```csharp
// 저장 시
public void SaveCertificate(byte[] p12Data, string password)
{
    using var cert = new X509Certificate2(p12Data, password);
    
    var metadata = new CertificateInfo
    {
        CertId = Guid.NewGuid().ToString(),
        // serialNumber 대신 해시 저장
        SerialNumberHash = ComputeSha256Hash(cert.SerialNumber),
        SubjectDN = cert.Subject,
        // ...existing code...
    };
    
    // P12 파일 저장 (실제 serialNumber는 여기에만 있음)
    File.WriteAllBytes("cert.p12", p12Data);
    File.WriteAllText("metadata.json", JsonSerializer.Serialize(metadata));
}

// 해시 함수
private string ComputeSha256Hash(string input)
{
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
    return Convert.ToHexString(bytes);
}
```

### 서명 시 실제 serialNumber 추출

```csharp
public SignResponse Sign(string certId, byte[] data, string password)
{
    var p12Data = File.ReadAllBytes(Path.Combine(_certPath, certId, "cert.p12"));
    
    // 비밀번호로 P12를 열 때만 실제 serialNumber 접근 가능
    using var cert = new X509Certificate2(p12Data, password);
    
    using var rsa = cert.GetRSAPrivateKey();
    var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    
    return new SignResponse
    {
        Signature = Convert.ToBase64String(signature),
        SerialNumber = cert.SerialNumber  // 서명 응답에만 포함
    };
}
```

### 변경된 metadata.json 구조

```json
{
  "certId": "4bd0a61a-a025-466c-ae7e-fc2b85efd970",
  "serialNumberHash": "A1B2C3D4E5F6...(SHA-256 해시)",
  "subjectDN": "CN=홍길동, O=2Check, C=KR",
  "notAfter": "2026-11-30T14:20:17Z",
  "isExpired": false
}
```

### 장점

| 항목 | 효과 |
|------|------|
| 파일 유출 시 | serialNumber 원본 알 수 없음 |
| 서명 시 | P12에서 직접 추출 (비밀번호 필요) |
| UI 표시 | 해시 앞 8자리만 표시 (예: A1B2C3D4...) |

### 주의사항
- 서버에서 해시로 인증서를 조회하려면 DB에도 해시 저장 필요
- 또는 현재처럼 서명 응답에 serialNumber 포함 (이 방식 권장)
