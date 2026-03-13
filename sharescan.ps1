<#
.SYNOPSIS
    Given a list of IPs, scans the shares on each one to see whats inside. It will scan the contents of files, and file names. Uses multiple threads to go faster.
    The aim is to have everything in one file, including any function definitions to make it easier to copy paste and run.
.DESCRIPTION
    This script scans the IPs listed in a file, writes results to a timestamped CSV file,
    and imports data into a SQLite database.
.PARAMETER serverList
    Path to the text file containing IP addresses to scan.
    Alias: -s
.PARAMETER outputCsvFile
    Name of the CSV file to output results (timestamp will be added automatically).
    Alias: -o
.PARAMETER dbPath
    Path to the SQLite database file.
    Alias: -d
.EXAMPLE
    .\file-content-search-match-per-keywordV14.ps1 -s "C:\Path\To\myIPs.txt" -o "C:\Path\To\results.csv" -d "C:\Path\To\mydb.db"
#>

param (
    [Alias('s')]
    [string]$serverList = "ips with shares.txt",
    [Alias('o')]
    [string]$outputCsvFile = ".\csv-dump\TEST_scan-result_shareFiles.csv",
    [Alias('d')]
    [string]$dbPath = ".\databases\TEST_database_shareFiles.db",
    [Alias('t')]
    [int]$throttle = 2
)

$ProgressPreference = 'Continue'

$keywords = @(
    'password','secret','confidential','private','credential','key','token','backup','export','database','db',
    'admin','login','user','account','creditcard','ssn','id','identity','bank','finance','payroll','tax','hr',
    'employee','insurance','medical','patient','report','statement','invoice','receipt','contract','agreement',
    'legal','audit','access','restricted','internal','source','config','settings','environment','env','vault',
    'master','certificate','cert','pem','pfx','ssh','rsa','pgp','gpg','recovery','restore','archive','old',
    'temp','tmp','test','sample','prod','dev','wwwroot',
    'oauth','jwt','saml','auth','authentication','authorization','session','cookie','bearer','clientid','clientsecret',
    'apikey','api_key','api-token','api_token','access_token','refresh_token','security','pin','challenge','twofactor','2fa',
    'mfa','totp','otp','aes','des','3des','blowfish','keyfile','keystore','truststore','privatekey','publickey','pubkey',
    'keypair','passphrase','encryption','decryption','crypt','crypto','hash','salt','md5','sha1','sha256','sha512',
    'iam','terraform','ansible','kubernetes','k8s','docker','container','compose','helm','cluster','node','pod',
    'serviceaccount','secretmanager','keyvault','system','root','sudo','administrator','superuser','passport','dob',
    'birthdate','address','phone','mobile','client','vendor','supplier','purchase','order','sales','transaction','payment',
    'bill','balance','salary','wage','bonus','benefit','compensation','paystub','tin','ein','nationalid','claim','policy',
    'health','diagnosis','treatment','prescription','doctor','nurse','appointment'
)

$fileExtensions = @(
    ".txt",".log",".csv",".tsv",".json",".jsonl",".xml",".yaml",".yml",".toml",
    ".ini",".cfg",".conf",".config",".properties",".env",".md",".markdown",".mdown",
    ".ps1",".psm1",".psd1",".ps1xml",".pssc",".bat",".cmd",".vbs",".js",".jsx",".ts",
    ".tsx",".py",".pyc",".pyw",".ipynb",".sh",".bash",".zsh",".fish",".sql",".ddl",
    ".pl",".pm",".rb",".r",".rdata",".php",".php3",".php4",".php5",".java",".class",
    ".jsp",".asp",".aspx",".cs",".vb",".cpp",".c",".h",".hpp",".cxx",".hxx",".cc",
    ".hh",".go",".rs",".swift",".kt",".kts",".dart",".lua",".html",".htm",".xhtml",
    ".css",".scss",".sass",".less",".svg",".kml",".gpx",".tex",".latex",".bib",".rtf",
    ".rst",".adoc",".asc",".text",".plain",".out",".err",".trace",".debug",".info",
    ".warn",".error",".access",".audit",".syslog",".eml",".msg",".ics",".vcf",".vcard",
    ".ldif",".mbox",".nfo",".diz",".reg",".inf",".url",".desktop",".list",".lst",".tab",
    ".diff",".patch",".gitignore",".gitattributes",".editorconfig",".htaccess",".htpasswd"
)

$tableName = "Scanned_IPs"
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$outputCsvFile = $outputCsvFile -replace '\.csv$', "_$timestamp.csv"

$csvDir = Split-Path $outputCsvFile -Parent
$dbDir  = Split-Path $dbPath -Parent

try {
    if (!(Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
    if (!(Test-Path $dbDir))  { New-Item -ItemType Directory -Path $dbDir  -Force | Out-Null }
} catch {
    Write-Host "Error: Unable to create output directories" -ForegroundColor Red
    Write-Host "Please provide valid absolute paths for all options used (e.g., C:\folder\results.csv)"
    Write-Host $_.Exception.Message
    exit 1
}

# CSV header
"IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error" | Out-File -FilePath $outputCsvFile -Encoding utf8

# Create SQLite table
$tableSchema = @"
CREATE TABLE IF NOT EXISTS $tableName (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    IP TEXT,
    ShareName TEXT,
    FileName TEXT,
    FilePath TEXT,
    CreationTime TEXT,
    TimeStamp TEXT,
    Size TEXT,
    Permissions TEXT,
    TriggerKeyword TEXT,
    Error TEXT
);
"@
$tableSchema | sqlite3 "$dbPath"

$lock = [System.Object]::new()

$servers = Get-Content $serverList -ErrorAction Stop
$scanStart = Get-Date

# Queue for displaying stuff
$writeQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$fileCounter = [System.Collections.Concurrent.ConcurrentDictionary[string,int]]::new()

# ────────────────────────────────────────────────────────────────
#   FUNCTION: Enumerate files (with batch parallel processing)
# ────────────────────────────────────────────────────────────────

function Get-AllFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,
        [ref]$ErrorList,
        [int]$BatchSize = 10000,
        [scriptblock]$OnBatch
    )

    $roboOutput = robocopy $RootPath NULL /L /S /NDL /NJH /NC /NP /FP /TS /BYTES /MT:128 2>&1

    ### code to print # of directories in share
    $separatorIndex = ($roboOutput | Select-String '^\s*-{3,}' | Select-Object -Last 1).LineNumber - 1
    $fileLines = $roboOutput[0..($separatorIndex - 1)]
    $summary = $roboOutput[$separatorIndex..($roboOutput.Count - 1)]

    $dirLine = $summary | Where-Object { $_ -match '^\s*Dirs\s*:' } | Select-Object -First 1
    $dirCount = ([string]($dirLine -replace '^\s*Dirs\s*:\s*', '' -replace '\s+.*')).Trim()
    Write-Host "    Total directories in $RootPath : $dirCount" -ForegroundColor DarkCyan

    $totalFiles = 0
    $fileLine = $summary | Where-Object { $_ -match '^\s*Files\s*:' } | Select-Object -First 1
    $totalFiles = ([string]($fileLine -replace '^\s*Files\s*:\s*', '' -replace '\s+.*')).Trim()
    Write-Host "    Total files in $RootPath : $totalFiles" -ForegroundColor DarkCyan

    $batch = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $fileLines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        if ($trimmed -match 'Access is denied|ERROR') {
            if ($null -ne $ErrorList) {
                $ErrorList.Value += @{
                    TargetObject = $trimmed
                    Exception    = $null
                    Message      = "Error on Accessing"
                }
            }
            continue
        }

        if ($trimmed -match '^(\d+)\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\\\\[^\s].+)$') {
            $batch.Add($trimmed)
        }

        if ($batch.Count -ge $BatchSize) {
            & $OnBatch $batch $totalFiles
            $batch.Clear()
        }
    }

    if ($batch.Count -gt 0) {
        & $OnBatch $batch $totalFiles
    }
}

# ────────────────────────────────────────────────────────────────
#   FUNCTION: Get share names using net view
# ────────────────────────────────────────────────────────────────

function Get-ShareNames {
    param($server)
    $shares = @()
    $output = net view "\\$server"

    $startCollecting = $false
    foreach ($line in $output) {
        if ($line -match '^Share name\s') {
            $startCollecting = $true
            $headerItems = $line -split '(?<= {2})\b'
            $headerLengths = $headerItems | ForEach-Object { $_.Length }
            continue
        }
        if ($line -match '^---' -or -not $startCollecting) { continue }
        if ($line -match '^The command completed successfully') {
            $startCollecting = $false
            continue
        }
        if ($line -match '^(.+?)\s{2,}') {
            $start = 0
            $values = for ($k = 0; $k -lt $headerLengths.Count; $k++) {
                if ($k -lt $headerLengths.Count - 1) {
                    $line.Substring($start, $headerLengths[$k])
                    $start += $headerLengths[$k]
                } else {
                    $line.Substring($start)
                }
            }
            $shareName = $values[0].Trim()
            $shares += $shareName
        }
    }
    return @($shares)
}

# ────────────────────────────────────────────────────────────────
#   MAIN LOOP - one IP at a time
# ────────────────────────────────────────────────────────────────

$ipIndex = 0
foreach ($server in $servers) {
    $ipIndex++
    Write-Host "[$ipIndex/$($servers.Count)] Scanning $server ..." -ForegroundColor Cyan

    # progress bar
    Write-Progress -Id 1 -Activity "Scanning IPs" -Status "[$ipIndex/$($servers.Count)] $server" -PercentComplete (($ipIndex / $servers.Count) * 100)

    $shares = Get-ShareNames $server
    if (-not $shares) {
        Write-Host "  No shares found or access denied on $server" -ForegroundColor Yellow
        continue
    }

    $shareIndex = 0
    foreach ($share in $shares) {
        $shareIndex++
        $timestamp = (Get-Date -Format "MM/dd/yyyy HH:mm:ss")
        $searchPath = "\\$server\$share"
        Write-Host "  [$shareIndex/$($shares.Count)] Scanning $searchPath ..." -ForegroundColor Cyan

        #progress bar
        Write-Progress -Id 2 -ParentId 1 -Activity "Scanning Shares" -Status "[$shareIndex/$($shares.Count)] $share" -PercentComplete (($shareIndex / $shares.Count) * 100)


        $fileKey = "$server\$share"
        $problems = @()
        #$tempAllPaths = Get-AllFiles -RootPath $searchPath -ErrorList ([ref]$problems)

        #$fileTot = $tempAllPaths.Count
        #Write-Host "    $fileTot files found in $searchPath"

        $fileJobs = @()
        $fileCounter[$fileKey] = 0

        Get-AllFiles -RootPath $searchPath -ErrorList ([ref]$problems) -BatchSize 10000 -OnBatch {
            param($batch, $totalFiles)

            $batchJobs = @()
            foreach ($rawLine in $batch) {
                $batchJobs += Start-ThreadJob -ThrottleLimit $script:throttle -ArgumentList $rawLine, $script:server, $script:share, $script:timestamp, $script:fileKey, $script:lock, $script:keywords, $script:fileExtensions, $script:outputCsvFile, $script:dbPath, $script:tableName, $script:fileCounter, $totalFiles -ScriptBlock {

                    $rawLine        = $args[0]
                    $server         = $args[1]
                    $share          = $args[2]
                    $timestamp      = $args[3]
                    $fileKey        = $args[4]
                    $lock           = $args[5]
                    $keywords       = $args[6]
                    $fileExtensions = $args[7]
                    $outputCsvFile  = $args[8]
                    $dbPath         = $args[9]
                    $tableName      = $args[10]
                    $fileCounter    = $args[11]
                    $totalFiles     = $args[12]

                    # Parse raw line into file object
                    if ($rawLine -notmatch '^(\d+)\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\\\\[^\s].+)$') { return }
                    $file = [PSCustomObject]@{
                        Name         = [System.IO.Path]::GetFileName($Matches[3])
                        FullName     = $Matches[3]
                        Length       = [long]$Matches[1]
                        Extension    = [System.IO.Path]::GetExtension($Matches[3])
                        CreationTime = [datetime]::Parse($Matches[2])
                    }

                    # increment counter and enqueue log
                    $count = $fileCounter.AddOrUpdate($fileKey, 1, [Func[string,int,int]]{ param($k,$v) $v+1 })
                    $writeQueue = $using:writeQueue
                    $writeQueue.Enqueue("   Scanning $($file.FullName)...")

                    try {
                        # ── 1. Filename keyword scan ──────────────────────────
                        $nameMatches = @($keywords.Where{ $file.FullName -match [regex]::Escape($_) })
                        if ($nameMatches.Count -gt 0) {
                            $perms = $null
                            # $acl = try { Get-Acl $file.FullName } catch { $perms = "Error: Unable to read permissions" }
                            $foundStr = $nameMatches -join ","
                            # $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"",Keyword in filename"
                            # $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','Keyword in filename');"
                            # queuing the writes
                            $writeQueue.Enqueue("INSERT|$server|$share|$($file.Name)|$($file.FullName)|$($file.CreationTime)|$timestamp|$($file.Length)|$perms|$foundStr|Keyword in filename")
                        }

                        # ── 2. Extension check — skip if unsupported ───────────
                        if ($fileExtensions -notcontains $file.Extension) {
                            # $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: unsupported extension'"
                            # $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: unsupported extension');"
                            # queue the writes
                            $writeQueue.Enqueue("INSERT|$server|$share|$($file.Name)|$($file.FullName)|$($file.CreationTime)|$timestamp|$($file.Length)|||Skipped: unsupported extension")
                            return
                        }

                        # ── 3. Size check — skip if > 1GB ─────────────────────
                        if ($file.Length -gt 1GB) {
                            # $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: file > 1GB'"
                            # $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: file > 1GB');"
                            #queue the writes
                            $writeQueue.Enqueue("INSERT|$server|$share|$($file.Name)|$($file.FullName)|$($file.CreationTime)|$timestamp|$($file.Length)|||Skipped: file > 1GB")
                            return
                        }

                        # ── 4. Content keyword scan ────────────────────────────
                        $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                        $contentMatches = @($keywords.Where{ $content -match [regex]::Escape($_) })
                        if ($contentMatches.Count -gt 0) {
                            $perms = $null
                            try { 
                                $acl = Get-Acl $file.FullName
                                $perms = $acl.AccessToString -replace "`r`n|`n|`r", " ; "
                            } catch { 
                                $perms = "Error: Unable to read permissions" 
                            }
                            $foundStr = $contentMatches -join ","
                            # $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"","
                            # $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','');"
                            #queue the writes
                            $writeQueue.Enqueue("INSERT|$server|$share|$($file.Name)|$($file.FullName)|$($file.CreationTime)|$timestamp|$($file.Length)|$perms|$foundStr|")
                        }
                    }
                    catch {
                        # $errPath  = $file.FullName -replace "'", "''"
                        # $errMsg   = $_.Exception.Message -replace "'", "''"
                        # $line = "$server,$share,,`'$errPath`',,$timestamp,,,,$errMsg"
                        # $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','','$errPath','','$timestamp','','','','Error on Accessing');"

                        $writeQueue.Enqueue("INSERT|$server|$share||$($file.FullName)||$timestamp||||Error on Accessing")
                    }
                }
            }

            # Monitor and wait for batch
            while ($batchJobs | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'NotStarted' }) {
                $currentCount = 0
                $fileCounter.TryGetValue($script:fileKey, [ref]$currentCount) | Out-Null
                Write-Progress -Id 3 -ParentId 2 -Activity "Scanning Files" -Status "[$currentCount/$totalFiles]" -PercentComplete (($currentCount / [Math]::Max([int]$totalFiles, 1)) * 100)
                $item = $null

                $inserts = [System.Collections.Generic.List[string]]::new()
                $csvLines = [System.Collections.Generic.List[string]]::new()
                $logLines = [System.Collections.Generic.List[string]]::new()

                while ($script:writeQueue.TryDequeue([ref]$item)) {
                    if ($item.StartsWith('INSERT|')) {
                        $parts = $item.Substring(7) -split '\|', 10
                        $csvLines.Add("$($parts[0]),$($parts[1]),$($parts[2]),$($parts[3]),$($parts[4]),$($parts[5]),$($parts[6]),""$($parts[7])"",""$($parts[8])"",""$($parts[9])""")
                        $inserts.Add("INSERT INTO $($script:tableName) (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$($parts[0] -replace "'","''")', '$($parts[1] -replace "'","''")', '$($parts[2] -replace "'","''")', '$($parts[3] -replace "'","''")', '$($parts[4])', '$($parts[5])', '$($parts[6])', '$($parts[7] -replace "'","''")', '$($parts[8] -replace "'","''")', '$($parts[9] -replace "'","''")');")
                    } else {
                        # this is for printing to console the files being scanned. comment it for less spam
                        #Write-Host $item -ForegroundColor Cyan
                    }
                }

                if ($csvLines.Count -gt 0) {
                    $csvLines | Out-File $script:outputCsvFile -Append -Encoding utf8
                }
                if ($inserts.Count -gt 0) {
                    $sql = "BEGIN TRANSACTION;`n" + ($inserts -join "`n") + "`nCOMMIT;"
                    $sql | sqlite3 $script:dbPath
                }

                Start-Sleep -Milliseconds 500
            }

            # Final drain
            $inserts = [System.Collections.Generic.List[string]]::new()
            $csvLines = [System.Collections.Generic.List[string]]::new()
            $item = $null
            while ($script:writeQueue.TryDequeue([ref]$item)) {
                if ($item.StartsWith('INSERT|')) {
                    $parts = $item.Substring(7) -split '\|', 10
                    $csvLines.Add("$($parts[0]),$($parts[1]),$($parts[2]),$($parts[3]),$($parts[4]),$($parts[5]),$($parts[6]),$($parts[7]),$($parts[8]),$($parts[9])")
                    $inserts.Add("INSERT INTO $($script:tableName) (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$($parts[0] -replace "'","''")', '$($parts[1] -replace "'","''")', '$($parts[2] -replace "'","''")', '$($parts[3] -replace "'","''")', '$($parts[4])', '$($parts[5])', '$($parts[6])', '$($parts[7] -replace "'","''")', '$($parts[8] -replace "'","''")', '$($parts[9] -replace "'","''")');")
                } else {
                    Write-Host $item -ForegroundColor Cyan
                }
            }
            if ($csvLines.Count -gt 0) {
                $csvLines | Out-File $script:outputCsvFile -Append -Encoding utf8
            }
            if ($inserts.Count -gt 0) {
                $sql = "BEGIN TRANSACTION;`n" + ($inserts -join "`n") + "`nCOMMIT;"
                $sql | sqlite3 $script:dbPath
            }

            $batchJobs | Wait-Job | Receive-Job | Out-Null
            $batchJobs | Remove-Job -Force
        }

        # Report enumeration errors
        $probInserts = [System.Collections.Generic.List[string]]::new()
        $probCsvLines = [System.Collections.Generic.List[string]]::new()

        foreach ($prob in $problems) {
            $errPath = $prob.TargetObject
            $errMsg  = $prob.Message
            $probCsvLines.Add("$script:server,$script:share,,`'$errPath`',,$script:timestamp,,,,$errMsg")
            $probInserts.Add("INSERT INTO $script:tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$script:server','$script:share','','$($errPath -replace "'","''")','','$script:timestamp','','','','$($errMsg -replace "'","''")');")
        }

        if ($probCsvLines.Count -gt 0) {
            $probCsvLines | Out-File $script:outputCsvFile -Append -Encoding utf8
        }
        if ($probInserts.Count -gt 0) {
            $sql = "BEGIN TRANSACTION;`n" + ($probInserts -join "`n") + "`nCOMMIT;"
            $sql | sqlite3 $script:dbPath
        }

        Write-Host "    Share $share done." -ForegroundColor Green
    }

    Write-Progress -Id 3 -Completed
    Write-Host "  $server completed." -ForegroundColor Green
}

Write-Progress -Id 1 -Completed
Write-Progress -Id 2 -Completed
Write-Progress -Id 3 -Completed

Write-Host "`nScan completed." -ForegroundColor Green
Write-Host "Results saved to: $outputCsvFile"
Write-Host "Database:         $dbPath"
$elapsed = (Get-Date) - $scanStart
Write-Host "Time taken:       $('{0:D2}h {1:D2}m {2:D2}s' -f $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds)"
