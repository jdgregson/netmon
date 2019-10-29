Param (
    [switch]$ShowFullIPv6,
    [switch]$NoLocalhost,
    [switch]$AggressiveDNS,
    [switch]$i,
    [switch]$Incoming,
    [switch]$l,
    [switch]$Listening,
    [switch]$m,
    [switch]$ml,
    [switch]$lm,
    [switch]$h,
    [switch]$help,
    [string]$fields = "ldfp",
    [string]$f = $fields,
    [string]$sort = "p",
    [string]$s = $sort
)


function Show-Help {
    Write-Host @"
 Usage: netmon [args and flags]

  -ShowFullIPv6       Do not truncate IPv6 addresses.
  -NoLocalhost        Do not show connections to or from localhost.
  -AggressiveDNS      Resolve hostnames more thoroughly (but slowly).
  -i, -Incoming       Only show incoming connections.
  -l, -Listening      Display a list of listening ports with associated process
                      names. Only displays ports bound on external interfaces by
                      default. Cannot be combined with any options besides -m.
  -m                  When combined with -l, this option will provide more
                      details, such as PIDs, ports bound on local interfaces,
                      and multiple processes listening on the same port.
  -h, -help           Show this help message.
  -s, -sort           Sort by field, according to the list of fields below.
  -f, -fields         Specify which fields to output, e.g.:
                      'netmon -f ldfP'. Available fields are:
                          l: Local endpoint
                          d: Direction of connection
                          f: Foreign endpoint
                          t: Protocol type
                          s: Connection state
                          h: DNS Hostname
                          i: Process ID
                          p: Process name
                          e: Executable path
                          c: Company
                          *: Display all fields
"@
}


function ColorMatch {
    #https://stackoverflow.com/questions/12609760
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $InputObject,
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Pattern,
        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Color='Red'
    )

    begin {
        $r = [regex]$Pattern
    } process {
        $ms = $r.matches($inputObject)
        $startIndex = 0
        foreach($m in $ms) {
            $nonMatchLength = $m.Index - $startIndex
            Write-Host $inputObject.Substring($startIndex, $nonMatchLength) -NoNew
            Write-Host $m.Value -Fore $Color -NoNew
            $startIndex = $m.Index + $m.Length
        }
        if($startIndex -lt $inputObject.Length) {
            Write-Host $inputObject.Substring($startIndex) -NoNew
        }
        Write-Host
    }
}


function Compress-IPv6Address {
    Param (
        [string]$Address = ""
    )

    if($Address -match "\[::\]" -or $Address -match "\[::1\]") {
        return $Address
    }
    $truncated = ($Address -replace "(\[([a-z0-9]*:)+)",":...:")
    return ($Address -split ":")[0] + $truncated
}


function Get-PortFromConnection {
    Param (
        [string]$connection
    )

    $localPort = ''
    for($i = $connection.Length - 1; $i -gt 0; $i--) {
        if($connection[$i] -ne ":") {
            $localPort += $connection[$i]
        } elseif($connection[$i] -eq ":") {
            break
        }
    }
    return $localPort | %{-join $_[$_.Length..0]} 
}


function Get-AddressFromConnection {
    Param (
        [string]$connection
    )

    $port = $(Get-PortFromConnection $connection)
    return $connection -Replace ":$port"
}


function Get-DNSName {
    Param (
        [Parameter(Mandatory = $true)]
        [string]$address
    )

    $resolution = try {
        if($AggressiveDNS) {
            Resolve-DNSName $address *>&1
        } else {
            Resolve-DNSName -QuickTimeout -DNSOnly $address *>&1
        }
    } catch {
        $_
    }

    if($resolution -and $resolution.NameHost) {
        return $resolution.NameHost
    } else {
        return ""
    }
}


function Test-IsLocalPort {
    Param (
        [string]$port = ""
    )

    return ($port -match "127.0.0.1" -or $port -match "\[::\]")
}


function Get-FieldMap {
    Param (
        [Parameter(Mandatory = $true)]
        [string]$fields
    )

    $output = @()
    $map = New-Object -Type PSobject -Property @{
        l = "LocalEndpoint"
        d = "Direction"
        f = "ForeignEndpoint"
        t = "Type"
        s = "State"
        h = "Hostname"
        i = "PID"
        p = "Process"
        e = "ExecutablePath"
        c = "Company"
    }

    if($fields -match "\*") {
        $output = ($map | Format-Table * | Out-String)
        $output = ($output -split "`n")[3] -split " "
    } else {
        foreach($f in ($fields -split "")) {
            if($map.$f) {
                $output += $map.$f
            }
        }
    }

    return $output
}


function Get-ListeningPorts {
    Param (
    )

    $_connections = (netstat -an)
    $ports = @()
    for($i=4; $i -lt $_connections.Count; $i++) {
        $p = $_connections[$i]
        if($p -match "LISTENING" -or $p -match "\*:\*") {
            $port = $p -replace '\s+',' ' -split ' '
            $ports += (Get-PortFromConnection $port[2])
        }
    }

    return $ports
}


function Get-ListeningPortsWithProcess {
    Param (
        [string]$cmd = 'netstat -aon|sls listening,"\*:\*"'
    )

    $_connections = Invoke-Expression "$cmd"
    $ports = @()
    for($i=4; $i -lt $_connections.Count; $i++) {
        $c = $_connections[$i] -replace '\s+',' ' -split ' '
        if($c[4] -eq "LISTENING") {
            $id = $c[5]
        } else {
            $id = $c[4]
        }
        $proc = (Get-Process -id $id).Name
        $ports += New-Object -TypeName PSObject -Property @{
            Protocol     = $($c[1])
            LocalAddress = $(Get-AddressFromConnection $c[2])
            LocalPort    = $(Get-PortFromConnection $c[2])
            PID          = $id
            Process      = $proc
        }
    }

    return $ports
}


function Show-ListeningPortsWithProcess {
    $procs = (Get-ListeningPortsWithProcess)
    if($m -or $lm -or $ml) {
        $procs | Sort @{e={$_.Process}; a=0},Protocol | `
            Format-Table Protocol,LocalAddress,LocalPort,Process,PID
    } else {
        $procs | Sort LocalPort -Unique | `
            Sort @{e={$_.Process}; a=0},Protocol | `
            Format-Table Protocol,LocalPort,Process | Where-Object {
                $_.LocalAddress -NotMatch "0.0.0.0" -and `
                $_.LocalAddress -NotMatch "[::1]"
            }
    }
}


function Get-Connections {
    Param (
        [string]$cmd = "netstat -no"
    )

    $_connections = Invoke-Expression "$cmd"
    $connections = @()
    for($i=4; $i -lt $_connections.Count; $i++) {
        $c = $_connections[$i] -replace '\s+',' ' -split ' '
        $connections += New-Object -TypeName PSobject -Property @{
            Protocol       = $($c[1])
            LocalAddress   = $(Get-AddressFromConnection $c[2])
            LocalPort      = $(Get-PortFromConnection $c[2])
            ForeignAddress = $(Get-AddressFromConnection $c[3])
            ForeignPort    = $(Get-PortFromConnection $c[3])
            State          = $($c[4])
            PID            = $($c[5])
        }
    }

    return $connections
}


function Show-Connections {
    $connections = @()
    $ports = (Get-ListeningPorts $script:IncludeLocalhost)
    foreach($c in (Get-Connections)) {
        if($ports -contains $c.LocalPort) {
            $dir = "<---------"
        } else {
            $dir = "--------->"
            if($incoming) {
                continue;
            }
        }

        if($c.LocalAddress -match "\[" -and -not $script:ShowFullIPv6) {
            $lEndpoint = "$(Compress-IPv6Address $c.LocalAddress):$($c.LocalPort)"
        } else {
            $lEndpoint = "$($c.LocalAddress):$($c.LocalPort)"
        }

        if($c.ForeignAddress -match "\[" -and -not $script:ShowFullIPv6) {
            $fEndpoint = "$(Compress-IPv6Address $c.ForeignAddress):$($c.ForeignPort)"
        } else {
            $fEndpoint = "$($c.ForeignAddress):$($c.ForeignPort)"
        }

        if($fields -match "h") {
            $hostname = (Get-DNSName $c.ForeignAddress)
        } else {
            $hostname = ""
        }

        if($fields -match "p" -or $fields -match "e" -or $fields -match "c" -or $fields -match "\*") {
            $process = (Get-Process -PID $c.PID)
            $proc = $process.Name
            $exepath = $process.Path
            $company = $process.Company
        } else {       
            $proc = ""
            $exepath = ""
            $company = ""
        }

        $connections += New-Object -Type PSobject -Property @{
            Type = $c.Protocol
            LocalEndpoint = "$lEndpoint"
            Direction = $dir
            ForeignEndpoint = $fEndpoint
            State = $c.State
            PID = $c.PID
            Process = $proc
            Hostname = $hostname
            ExecutablePath = $exepath
            Company = $company
        }
    }

    $fieldMap = (Get-FieldMap $fields)
    $sortField = @(Get-FieldMap $sort)[0]

    if($connections) {
        if($script:NoLocalhost) {
            ($connections |
                Sort-Object -Property $sortField |
                where {$_.LocalEndpoint -notmatch "127.0.0.1"} | 
                where {$_.LocalEndpoint -notmatch "\[::\]"} |
                Format-Table $fieldMap |
                Out-String
            ) | ColorMatch "<---------" -Color "DarkRed"
        } else {
            ($connections |
                Sort-Object -Property $sortField |
                Format-Table $fieldMap | 
                Out-String
            ) | ColorMatch "<---------" -Color "DarkRed"
        }
    }
}


function Main {
    if($f -ne $fields) {
        $fields = $f
    }
    if($s -ne $sort) {
        $sort = $s
    }
    if($i -or $Incoming) {
        $Incoming = $true
        $i = $true
    }
    if($l -or $Listening -or $ml -or $lm) {
        Show-ListeningPortsWithProcess
        exit
    }
    Show-Connections
}


if($h -or $help) {
    Show-Help
} else {
    Main
}
