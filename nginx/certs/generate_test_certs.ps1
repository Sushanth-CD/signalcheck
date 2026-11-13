# Script to generate ephemeral self-signed certificates for local HTTPS testing
$CertDir = "C:\Projects\cyber-security-awareness-platform\nginx\certs"
if (!(Test-Path $CertDir)) {
    New-Item -ItemType Directory -Path $CertDir -Force | Out-Null
}

$cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddDays(30)
$pwd = ConvertTo-SecureString -String "SignalCheck123" -Force -AsPlainText
$pfxPath = "$CertDir\cert.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null

# Export PEM format if openssl is available, or write self-signed PEM markers
Write-Output "Self-signed certificate generated at $pfxPath"
