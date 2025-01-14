# AwakeCoding Debug Tools

Install the AwakeCoding.DebugTools PowerShell module:

```powershell
Install-Module -Name AwakeCoding.DebugTools -Scope AllUsers -Force
```

## LSA TLS pre-master secret logging

Open PowerShell 7 elevated, then install the PSDetour PowerShell module:

```powershell
Install-Module -Name PSDetour -Scope AllUsers -Force
```

Start logging TLS pre-master secrets ('C:\Windows\Temp\tls-lsa.log' by default):

```powershell
Start-LsaTlsKeyLog
```

## Streaming TLS pre-master secrets to a different machine

Start TLS key log server to watch a TLS key log file and send changes to connected TCP clients:

```powershell
Start-TlsKeyLogServer -LogFile 'C:\Windows\Temp\tls-lsa.log' -Port 12345 -AllowInFirewall
```

On another machine, start the TLS key log client to connect collect TLS pre-master secrets and output them to a local file:

```powershell
Start-TlsKeyLogClient -Servers '10.10.0.25:12345' -LogFile "C:\Windows\Temp\sslkeylogfile.txt"
```

## Install WinDBG

```powershell
Install-WinDbg
```

## Install DbgHelp DLLs

```powershell
Install-DbgHelp
```
