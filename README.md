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

## Install WinDBG

```powershell
Install-WinDbg
```

## Install DbgHelp DLLs

```powershell
Install-DbgHelp
```
