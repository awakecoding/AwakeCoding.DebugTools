#
# This tool was made possible thanks to Jordan Borean:
# https://github.com/jborean93
# https://twitter.com/BoreanJordan
#
# References:
# https://b.poc.fun/decrypting-schannel-tls-part-1/
# https://gist.github.com/jborean93/6c1f1b3130f2675f1618da56633eb1fa
#

function Start-LsaTlsKeyLog {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$false)]
        [string] $LogFile
    )

    if (-Not (Get-Module -ListAvailable -Name PSDetour)) {
        throw "The 'PSDetour' module is required: Install-Module -Name PSDetour -Scope AllUsers -Force"
    }

    $CurrentPrincipal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $CurrentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This cmdlet requires Administrator privileges. Please run PowerShell 7 as Administrator."
    }

    if ($PSVersionTable.PSEdition -ne 'Core') {
        throw "This cmdlet requires PowerShell 7"
    }

    if ([string]::IsNullOrEmpty($LogFile)) {
        $WindowsTemp = Join-Path $Env:SystemRoot 'Temp'
        $LogFile = Join-Path $WindowsTemp 'tls-lsa.log'
    }

    $LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)
    $session = New-PSDetourSession -ProcessId lsass -ErrorAction Stop
    try {
        Invoke-Command -Session $session -ScriptBlock {

            Function Get-SecretKey {
                param([Parameter(Mandatory)][IntPtr]$KeyPtr)

                $dddbStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($KeyPtr)
                $ssl3StructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($dddbStructPtr, 0x10)
                $uuurStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ssl3StructPtr, 0x20)
                $mskyStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($uuurStructPtr, 0x10)

                $secretLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($mskyStructPtr, 0x10)
                $secretPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($mskyStructPtr, 0x18)

                $secret = [byte[]]::new($secretLength)
                [System.Runtime.InteropServices.Marshal]::Copy($secretPtr, $secret, 0, $secret.Length)
                , $secret
            }

            $tlsLog = [System.IO.File]::Open($using:LogFile, "Append", "Write", "Read")
            $tlsWriter = [System.IO.StreamWriter]::new($tlsLog)
            $tlsWriter.AutoFlush = $true
            $state = @{
                GetSecretKeyFunc = ${function:Get-SecretKey}.ToString()
                ClientRandoms    = [Hashtable]::Synchronized(@{})
                Stages           = [Hashtable]::Synchronized(@{})
                TlsWriter        = $tlsWriter
            }

            $ncrypt = @{ DllName = 'ncrypt.dll' }
            Start-PSDetour -State $state -Hook @(
                New-PSDetourHook @ncrypt -MethodName SslHashHandshake -Action {
                    <#
                    .DESCRIPTION
                    Called for TLS 1.3 sessions and TLS 1.2 with RFC 7627 session hashing.
                    It is used to capture the client_random value in the TLS ClientHello
                    message for future reference in the other hooked functions.
                    #>
                    [OutputType([int])]
                    param (
                        [IntPtr]$SslProvider,
                        [IntPtr]$HandshakeHash,
                        [IntPtr]$InputBytes,
                        [int]$InputLength,
                        [int]$Flags
                    )

                    # This buffer is the TLS packets, we are interested in the ClientHello
                    # which is msgType 1 and version 0x0303 (TLS 1.2)
                    $data = [byte[]]::new($InputLength)
                    [System.Runtime.InteropServices.Marshal]::Copy($InputBytes, $data, 0, $data.Length)

                    $msgType = $data[0]
                    $version = if ($msgType -eq 1) {
                        [System.BitConverter]::ToUInt16($data, 4)
                    }

                    if ($msgType -eq 1 -and $version -eq 0x0303) {
                        $crandom = [byte[]]::new(32)
                        [System.Buffer]::BlockCopy($data, 6, $crandom, 0, $crandom.Length)

                        $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        $this.State.ClientRandoms[$tid] = $crandom
                    }

                    $this.Invoke($SslProvider, $HandshakeHash, $InputBytes, $InputLength, $Flags)
                }
                New-PSDetourHook @ncrypt -MethodName SslExpandTrafficKeys -Action {
                    <#
                    .DESCRIPTION
                    Called for TLS 1.3 sessions twice.
                    First is for the handshake traffic key and second for the first
                    handshake traffic secret.
                    The function is undocumented but Param4 is the client secret and Param5
                    is the server secret.
                    #>
                    [OutputType([int])]
                    param (
                        [IntPtr]$Param1,
                        [IntPtr]$Param2,
                        [IntPtr]$Param3,
                        [IntPtr]$Param4,
                        [IntPtr]$Param5
                    )

                    $res = $this.Invoke($Param1, $Param2, $Param3, $Param4, $Param5)

                    $null = New-Item -Path Function:\Get-SecretKey -Value ([ScriptBlock]::Create(
                            $this.State.GetSecretKeyFunc))
                    $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId

                    if ($this.State.Stages[$tid]) {
                        $suffix = 'TRAFFIC_SECRET_0'
                    }
                    else {
                        $suffix = 'HANDSHAKE_TRAFFIC_SECRET'
                        $this.State.Stages[$tid] = $true
                    }

                    $clientSecret = Get-SecretKey -KeyPtr $Param4
                    $serverSecret = Get-SecretKey -KeyPtr $Param5
                    $cr = $this.State.ClientRandoms[$tid]

                    ($this.State.TlsWriter).WriteLine('CLIENT_{0} {1} {2}', $suffix,
                        [System.Convert]::ToHexString($cr),
                        [System.Convert]::ToHexString($clientSecret))
                    ($this.State.TlsWriter).WriteLine('SERVER_{0} {1} {2}', $suffix,
                        [System.Convert]::ToHexString($cr),
                        [System.Convert]::ToHexString($serverSecret))

                    $res
                }
                New-PSDetourHook @ncrypt -MethodName SslExpandExporterMasterKey -Action {
                    <#
                    .DESCRIPTION
                    Called for TLS 1.3 sessions.
                    Gets the exporter secret through the undocumented function.
                    #>
                    [OutputType([int])]
                    param (
                        [IntPtr]$Param1,
                        [IntPtr]$Param2,
                        [IntPtr]$Param3,
                        [IntPtr]$Param4
                    )

                    $res = $this.Invoke($Param1, $Param2, $Param3, $Param4)

                    $null = New-Item -Path Function:\Get-SecretKey -Value ([ScriptBlock]::Create(
                            $this.State.GetSecretKeyFunc))
                    $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId

                    $secret = Get-SecretKey -KeyPtr $Param4
                    $cr = $this.State.ClientRandoms[$tid]

                    ($this.State.TlsWriter).WriteLine('EXPORTER_SECRET {0} {1}',
                        [System.Convert]::ToHexString($cr),
                        [System.Convert]::ToHexString($secret))

                    $res
                }
                New-PSDetourHook @ncrypt -MethodName SslGenerateSessionKeys -Action {
                    <#
                    .DESCRIPTION
                    Called for TLS 1.2 sessions.
                    Gets the master secret key for TLS 1.2 sessions.
                    #>
                    [OutputType([int])]
                    param (
                        [IntPtr]$SslProvider,
                        [IntPtr]$MasterKey,
                        [IntPtr]$ReadKey,
                        [IntPtr]$WriteKey,
                        [IntPtr]$ParameterList,
                        [int]$Flags
                    )

                    <#
                    typedef struct _NCryptBufferDesc {
                        ULONG         ulVersion;
                        ULONG         cBuffers;
                        PNCryptBuffer pBuffers;
                    } NCryptBufferDesc, *PNCryptBufferDesc;

                    typedef struct _NCryptBuffer {
                        ULONG cbBuffer;
                        ULONG BufferType;
                        PVOID pvBuffer;
                    } NCryptBuffer, *PNCryptBuffer;
                    #>
                    $bufferCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($ParameterList, 4)
                    $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ParameterList, 8)
                    for ($i = 0; $i -lt $bufferCount; $i++) {
                        $bufferSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
                        $bufferType = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)
                        $bufferValuePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)
                        if ($bufferType -eq 20) {
                            # NCRYPTBUFFER_SSL_CLIENT_RANDOM
                            $cr = [byte[]]::new($bufferSize)
                            [System.Runtime.InteropServices.Marshal]::Copy($bufferValuePtr, $cr, 0, $cr.Length)
                            break
                        }

                        $bufferPtr = [IntPtr]::Add($bufferPtr, 8 + ([IntPtr]::Size))
                    }

                    # The client_random should always be in the ParameterList but the
                    # fallback is still used.
                    if (-not $cr) {
                        $cr = ($this.State.ClientRandoms)[([System.Threading.Thread]::CurrentThread.ManagedThreadId)]
                    }

                    $ssl5StructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($MasterKey, 0x10)
                    $secretPtr = [IntPtr]::Add($ssl5StructPtr,
                        ([IntPtr]::Size -eq 8 ? 28 : 20))

                    $secret = [byte[]]::new(48)
                    [System.Runtime.InteropServices.Marshal]::Copy($secretPtr, $secret, 0, $secret.Length)

                    ($this.State.TlsWriter).WriteLine('CLIENT_RANDOM {0} {1}',
                        [System.Convert]::ToHexString($cr),
                        [System.Convert]::ToHexString($secret))

                    $this.Invoke($SslProvider, $MasterKey, $ReadKey, $WriteKey, $ParameterList, $Flags)
                }
            )

            Write-Host "SSLKEYLOGFILE=`'$using:LogFile`'"
            Write-Host "Press any key to stop SChannel TLS logging..."
            $null = $host.UI.RawUI.ReadKey()

            Stop-PSDetour

            $tlsWriter.Dispose()
            $tlsLog.Dispose()
        }
    }
    finally {
        $session | Remove-PSSession
    }
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading;

public class FileTcpStreamer
{
    private TcpListener listener;
    private List<TcpClient> clients;
    private string filePath;
    private FileStream fileStream;
    private StreamReader reader;
    private Thread acceptThread;
    private Thread fileWatchThread;
    private volatile bool running;

    public FileTcpStreamer(string filePath, int port)
    {
        this.filePath = filePath;
        this.listener = new TcpListener(IPAddress.Any, port);
        this.clients = new List<TcpClient>();
        this.running = false;
    }

    public void Start()
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}");

        this.running = true;

        // Start TCP listener
        listener.Start();
        Console.WriteLine($"Listening for connections on port {((IPEndPoint)listener.LocalEndpoint).Port}...");

        // Start accepting clients
        acceptThread = new Thread(AcceptClients);
        acceptThread.IsBackground = true;
        acceptThread.Start();

        // Start watching the file
        fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        reader = new StreamReader(fileStream);
        reader.BaseStream.Seek(0, SeekOrigin.End); // Start at the end of the file

        fileWatchThread = new Thread(WatchFile);
        fileWatchThread.IsBackground = true;
        fileWatchThread.Start();
    }

    private void AcceptClients()
    {
        while (running)
        {
            try
            {
                TcpClient client = listener.AcceptTcpClient();
                lock (clients)
                {
                    clients.Add(client);
                }
                Console.WriteLine($"Client connected from {((IPEndPoint)client.Client.RemoteEndPoint).Address}");
            }
            catch (SocketException)
            {
                if (!running) break;
            }
        }
    }

    private void WatchFile()
    {
        while (running)
        {
            try
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    BroadcastLine(line);
                }

                Thread.Sleep(100);
            }
            catch (IOException ex)
            {
                Console.WriteLine($"File error: {ex.Message}");
                break;
            }
        }
    }

    private void BroadcastLine(string line)
    {
        lock (clients)
        {
            for (int i = clients.Count - 1; i >= 0; i--)
            {
                TcpClient client = clients[i];
                try
                {
                    StreamWriter writer = new StreamWriter(client.GetStream());
                    writer.AutoFlush = true;
                    writer.WriteLine(line);
                }
                catch (Exception)
                {
                    Console.WriteLine($"Client disconnected.");
                    client.Close();
                    clients.RemoveAt(i);
                }
            }
        }
    }

    public void Stop()
    {
        Console.WriteLine("Stopping...");
        running = false;

        listener.Stop();

        if (acceptThread != null && acceptThread.IsAlive)
            acceptThread.Join();

        if (fileWatchThread != null && fileWatchThread.IsAlive)
            fileWatchThread.Join();

        lock (clients)
        {
            foreach (var client in clients)
            {
                client.Close();
            }
            clients.Clear();
        }

        reader?.Close();
        fileStream?.Close();

        Console.WriteLine("Stopped.");
    }
}
"@ -Language CSharp

function Start-TlsKeyLogServer {
    param (
        [Parameter(Position = 0)]
        [string] $LogFile,

        [Parameter(Position = 1)]
        [int] $Port = 12345,

        [switch] $AllowInFirewall
    )

    if ([string]::IsNullOrEmpty($LogFile)) {
        $WindowsTemp = Join-Path $Env:SystemRoot 'Temp'
        $LogFile = Join-Path $WindowsTemp 'tls-lsa.log'
    }

    $LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)

    if ($AllowInFirewall) {
        $DisplayName = "Allow TLS Key Log Server"
        $CurrentRule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue

        if ($CurrentRule) {
            $CurrentPorts = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $CurrentRule |
                Where-Object { $_.Protocol -eq "TCP" } | Select-Object -ExpandProperty LocalPort

            if (-Not ($CurrentPorts -Contains $Port)) {
                $CurrentRule | Remove-NetFirewallRule
                $CurrentRule = $null
            }
        }

        if ($null -eq $CurrentRule) {
            Write-Host "Creating '$DisplayName' firewall rule for TCP port $Port"
            New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
        }
    }

    Write-Host "Serving TLS key log '$LogFile' on TCP port $Port"

    $streamer = New-Object FileTcpStreamer($LogFile, $Port)
    $streamer.Start()

    try {
        Write-Host "Press any key to stop..."
        [Console]::ReadLine() | Out-Null
    } finally {
        $streamer.Stop()
    }
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;

public class TcpClientAggregator
{
    private List<string> servers;
    private string outputFile;
    private int retryInterval;
    private volatile bool running;
    private List<Thread> connectionThreads;

    public TcpClientAggregator(string[] servers, string outputFile, int retryInterval)
    {
        this.servers = new List<string>(servers);
        this.outputFile = outputFile;
        this.retryInterval = retryInterval;
        this.running = false;
        this.connectionThreads = new List<Thread>();
    }

    public void Start()
    {
        if (servers.Count == 0)
            throw new ArgumentException("No servers specified.");

        if (string.IsNullOrEmpty(outputFile))
            throw new ArgumentException("Output file must be specified.");

        Directory.CreateDirectory(Path.GetDirectoryName(outputFile) ?? ".");
        running = true;

        foreach (var server in servers)
        {
            var thread = new Thread(() => ConnectToServer(server));
            thread.IsBackground = true;
            thread.Start();
            connectionThreads.Add(thread);
        }
    }

    private void ConnectToServer(string server)
    {
        string host;
        int port = 12345; // Default port

        var parts = server.Split(':');
        if (parts.Length == 2 && int.TryParse(parts[1], out int parsedPort))
        {
            host = parts[0];
            port = parsedPort;
        }
        else if (parts.Length == 1)
        {
            host = parts[0];
        }
        else
        {
            Console.WriteLine($"Invalid server address: {server}");
            return;
        }

        while (running)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    Console.WriteLine($"Connecting to {host}:{port}...");
                    var connectTask = client.ConnectAsync(host, port);
                    if (!connectTask.Wait(5000)) // Timeout for Connect
                    {
                        throw new TimeoutException($"Connection to {host}:{port} timed out.");
                    }

                    Console.WriteLine($"Connected to {host}:{port}.");

                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream))
                    {
                        while (running)
                        {
                            if (!stream.DataAvailable)
                            {
                                Thread.Sleep(100); // Avoid busy-waiting
                                continue;
                            }

                            string line = reader.ReadLine();
                            if (line != null)
                            {
                                File.AppendAllText(outputFile, $"{line}{Environment.NewLine}");
                            }
                            else
                            {
                                throw new IOException("Stream closed by server.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{host}:{port}] Error: {ex.Message}");
            }

            if (running)
            {
                Console.WriteLine($"Retrying connection to {host}:{port} in {retryInterval} seconds...");
                Thread.Sleep(retryInterval * 1000);
            }
        }
    }

    public void Stop()
    {
        Console.WriteLine("Stopping...");
        running = false;

        foreach (var thread in connectionThreads)
        {
            if (thread.IsAlive)
                thread.Join();
        }

        Console.WriteLine("Stopped.");
    }
}
"@ -Language CSharp

function Start-TlsKeyLogClient {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string[]] $Servers,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $LogFile,
        [int] $RetryInterval = 10
    )

    $LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)

    Write-Host "Writing TLS key log to '$LogFile'"

    $aggregator = [TcpClientAggregator]::new($Servers, $LogFile, $RetryInterval)
    $aggregator.Start()

    try {
        Write-Host "Press any key to stop..."
        [Console]::ReadLine() | Out-Null
    } finally {
        $aggregator.Stop()
    }
}

function Install-WinDbg {
    param(
        [switch] $Start
    )

    # Change default progress preference (faster downloads)
    $DefaultProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    Write-Host "Downloading windbg.appinstaller (XML manifest file)"
    $AppInstallerUrl = "https://aka.ms/windbg/download"
    $AppInstallerPath = Join-Path -Path $env:TEMP -ChildPath "windbg.appinstaller"
    Invoke-WebRequest -Uri $AppInstallerUrl -OutFile $AppInstallerPath

    Write-Host "Parsing .appinstaller XML for windbg.msixbundle URL"
    [xml]$AppInstallerXml = Get-Content -Path $AppInstallerPath
    $NamespaceManager = New-Object System.Xml.XmlNamespaceManager($AppInstallerXml.NameTable)
    $NamespaceManager.AddNamespace("ns", "http://schemas.microsoft.com/appx/appinstaller/2018")
    $BundleUrl = $AppInstallerXml.SelectSingleNode("//ns:MainBundle", $NamespaceManager).Uri

    Write-Host "Downloading windbg.msixbundle (actual package file)"
    $MsixBundlePath = Join-Path -Path $env:TEMP -ChildPath "windbg.msixbundle"
    Invoke-WebRequest -Uri $BundleUrl -OutFile $MsixBundlePath
    $ProgressPreference = $DefaultProgressPreference

    Write-Host "Invoking Add-AppxPackage to install windbg.msixbundle"
    if ($PSEdition -eq 'Core') {
        $Command = "Add-AppxPackage -Path `"$MsixBundlePath`""
        Start-Process powershell.exe -ArgumentList "-Command", $Command -Wait
    } else {
        Add-AppxPackage -Path $MsixBundlePath
    }

    Write-Host "WinDbg is now installed!"

    # Start WinDbg if the -Start switch is used
    if ($Start) {
        $WinDbgAppID = (Get-StartApps | Where-Object { $_.Name -eq 'WinDbg' }).AppID
        if ($WinDbgAppID) {
            Write-Host "Launching WinDbg..."
            Start-Process "shell:AppsFolder\$WinDbgAppID"
        } else {
            Write-Warning "WinDbg not found or could not be started."
        }
    }
}

function Install-DbgHelp {
    param(
        [string] $SymbolsPath,
        [string] $DbgHelpDir,
        [switch] $DownloadOnly
    )

    if (-Not $DownloadOnly) {
        $CurrentPrincipal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
        if (-Not $CurrentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "This cmdlet requires Administrator privileges. Please run PowerShell as Administrator."
        }
    }

    if ([string]::IsNullOrEmpty($SymbolsPath)) {
        $SymbolsPath = Join-Path $Env:SystemDrive "symbols"
    }

    if ([string]::IsNullOrEmpty($DbgHelpDir)) {
        $DbgHelpDir = Join-Path $SymbolsPath "DbgHelp"
    }

    $ProgressPreference = "SilentlyContinue"

    New-Item -ItemType Directory -Path $SymbolsPath -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $DbgHelpDir -ErrorAction SilentlyContinue | Out-Null

    if (-Not $DownloadOnly) {
        $NtSymbolPath = "srv*$SymbolsPath*https://msdl.microsoft.com/download/symbols"
        Write-Host "Setting _NT_SYMBOL_PATH to '$NtSymbolPath'"
        [Environment]::SetEnvironmentVariable("_NT_SYMBOL_PATH", $NtSymbolPath, "Machine")
    }
    
    Write-Host "Downloading DbgHelp DLLs to '$DbgHelpDir'"
    $NativeDir = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "arm64" } else { "amd64" }
    $Packages = @{
        "Microsoft.Debugging.Platform.DbgEng" = "content/$NativeDir/dbghelp.dll";
        "Microsoft.Debugging.Platform.SrcSrv" = "content/$NativeDir/srcsrv.dll";
        "Microsoft.Debugging.Platform.SymSrv" = "content/$NativeDir/symsrv.dll"
    }
    foreach ($Package in $Packages.GetEnumerator()) {
        $PackageName = $Package.Key
        $FilePath = $Package.Value
        $TempNupkgPath = "$Env:TEMP\$PackageName.zip"
        $TempExtractPath = "$Env:TEMP\$PackageName"
        $DownloadUrl = "https://www.nuget.org/api/v2/package/$PackageName"
    
        # Download raw .nupkg as a .zip file
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempNupkgPath
        Expand-Archive -Path $TempNupkgPath -DestinationPath $TempExtractPath
    
        $FileToCopy = Join-Path $TempExtractPath $FilePath
        if (Test-Path -Path $FileToCopy) {
            Copy-Item -Path $FileToCopy -Destination $DbgHelpDir
        }

        Remove-Item -Path $TempNupkgPath | Out-Null
        Remove-Item -Path $TempExtractPath -Recurse | Out-Null
    }

    $DbgHelpDllPath = Join-Path $DbgHelpDir "dbghelp.dll"
    Write-Host "DbgHelp DLL path is '$DbgHelpDllPath'"

    if (-Not $DownloadOnly) {
        Write-Host "Registering DbgHelp DLL with Sysinternals tools"

        $DefaultUserReg = "HKLM\TempDefault"
        $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
        reg load $DefaultUserReg $NtuserDatPath | Out-Null
        $HKDU = "Registry::$DefaultUserReg"
        @('Process Monitor', 'Process Explorer') | ForEach-Object {
            $RegPath = "$HKDU\Software\Sysinternals\$_"
            New-Item -Path $RegPath -Force | Out-Null
            Set-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -Type DWORD
            Set-ItemProperty -Path $RegPath -Name "DbgHelpPath" -Value $DbgHelpDllPath -Type String

            $RegPath = "HKCU:\Software\Sysinternals\$_"
            New-Item -Path $RegPath -Force | Out-Null
            Set-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -Type DWORD
            Set-ItemProperty -Path $RegPath -Name "DbgHelpPath" -Value $DbgHelpDllPath -Type String
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        reg unload $DefaultUserReg | Out-Null
    }
}
