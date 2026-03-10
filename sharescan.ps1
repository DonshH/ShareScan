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
    .\file-content-search-match-per-keywordV2.ps1 -s "C:\Path\To\myIPs.txt" -o "C:\Path\To\results.csv" -d "C:\Path\To\mydb.db"
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

# Pre-compile a single alternation regex for all keywords — far faster than 150 separate passes
$keywordRegex = ($keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

# HashSet for O(1) extension lookup instead of O(n) array scan per file
$fileExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$fileExtensions,
    [System.StringComparer]::OrdinalIgnoreCase
)

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

# ────────────────────────────────────────────────────────────────
#   SYNCHRONIZED PROGRESS TRACKING
# ────────────────────────────────────────────────────────────────

$syncProgress = [System.Collections.Hashtable]::Synchronized(@{
    IPs      = @{ Current = 0; Total = 0; Status = "Initializing..." }
    CurrentIP = ""
    Shares   = @{}   # server → @{Current=; Total=; Status=}
    LogQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
})

# ConcurrentDictionary so the monitoring loop can safely enumerate keys while the IP job writes entries.
# "server\share" → @{Total=; FileName=""}
$fileProgress = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

# Atomic int counter per share — passed via -ArgumentList to nested file jobs so the live reference survives serialization.
# int values are safe: AddOrUpdate on an int is truly atomic across thread boundaries.
$fileCounter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()


# ── Writer queue ─────────────────────────────────────────────────
# All CSV lines and DB INSERTs are enqueued here as @{Line=; Insert=}
# and written by a single dedicated thread — no concurrent file I/O,
# no Monitor locks, no orphaned sqlite3 processes.
$writeQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$dbDone     = [System.Collections.Hashtable]::Synchronized(@{ Value = $false })

$servers = Get-Content $serverList -ErrorAction Stop | Where-Object { $_.Trim() -ne '' }
$syncProgress.IPs.Total = $servers.Count

$ipJobs = [System.Collections.Generic.List[object]]::new()
$scanStart = Get-Date

# ────────────────────────────────────────────────────────────────
#   WRITER JOB — single thread, owns CSV and sqlite3 exclusively
# ────────────────────────────────────────────────────────────────
$dbWriterJob = Start-ThreadJob -ArgumentList $writeQueue, $dbDone, $dbPath, $outputCsvFile -ScriptBlock {
    $writeQueue    = $args[0]
    $dbDone        = $args[1]
    $dbPath        = $args[2]
    $outputCsvFile = $args[3]

    "PRAGMA journal_mode=WAL;" | sqlite3 $dbPath

    $item = $null
    while (-not $dbDone.Value -or -not $writeQueue.IsEmpty) {
        if ($writeQueue.TryDequeue([ref]$item)) {
            if ($null -ne $item.Line)   { $item.Line   | Out-File $outputCsvFile -Append -Encoding utf8 }
            if ($null -ne $item.Insert) { $item.Insert | sqlite3 $dbPath }
        } else {
            Start-Sleep -Milliseconds 50
        }
    }
}


# ────────────────────────────────────────────────────────────────
#   MAIN LOOP - Launch one thread job per IP
# ────────────────────────────────────────────────────────────────

foreach ($server in $servers) {
    $ipJobs.Add((Start-ThreadJob -ThrottleLimit $throttle -ArgumentList $server, $fileCounter, $writeQueue -ScriptBlock {

        $server          = $args[0]
        $fileCounter     = $args[1]   # ConcurrentDictionary[string,int] — atomic int counter, survives serialization
        $writeQueue      = $args[2]   # ConcurrentQueue[object] — enqueue @{Line=;Insert=} for the dedicated writer
        $fileProgress    = $using:fileProgress  # written by IP job only — $using: preserves live reference
        $syncProgress    = $using:syncProgress
        $keywordRegex     = $using:keywordRegex
        $fileExtensionSet = $using:fileExtensionSet
        $dbPath          = $using:dbPath
        $tableName       = $using:tableName

    # ────────────────────────────────────────────────────────────────
    #   FUNCTION: Enumerate files (with batch parallel processing)
    # ────────────────────────────────────────────────────────────────

	function Get-AllFiles {
		[CmdletBinding()]
		param(
			[Parameter(Mandatory)]
			[string]$RootPath,
			[ref]$ErrorList
		)

		$results = [System.Collections.Generic.List[object]]::new()

		try {
			$enumerator = [System.IO.Directory]::EnumerateFiles($RootPath, '*', 'AllDirectories').GetEnumerator()
		} catch {
			if ($null -ne $ErrorList) {
				$ErrorList.Value += @{
					TargetObject = $RootPath
					Exception    = $_.Exception
					Message      = "Error on Accessing"
				}
			}
			return $results
		}

		while ($enumerator.MoveNext()) {
			$path = $enumerator.Current
			try {
				$f = [System.IO.FileInfo]::new($path)
				$results.Add([PSCustomObject]@{
					Name         = $f.Name
					FullName     = $f.FullName
					Length       = $f.Length
					Extension    = $f.Extension
					CreationTime = $f.CreationTime
				})
			} catch {
				if ($null -ne $ErrorList) {
					$ErrorList.Value += @{ TargetObject = $path; Exception = $_.Exception; Message = $_.Exception.Message }
				}
			}
		}
		return $results
	}

    # ────────────────────────────────────────────────────────────────
    #   FUNCTION: Get share names using net view
    # ────────────────────────────────────────────────────────────────

	function Get-ShareNames {
		param($server)
		try {
			$output = net view "\\$server" 2>&1
			if ($LASTEXITCODE -ne 0) {
				throw "net view failed with exit code $LASTEXITCODE`: $($output -join ' ')"
			}
		} catch {
			$syncProgress.LogQueue.Enqueue(@{ Msg = "  Get-ShareNames error on ${server}: $($_.Exception.Message)"; Color = "Red" })
			return @()
		}

		# Filter to lines that contain 'Disk' in the Type column — works across locales and versions
		$shares = $output | Where-Object { $_ -match '\bDisk\b' } | ForEach-Object {
			# Share name is always the first whitespace-delimited token on the line
			($_ -split '\s+')[0].Trim()
		} | Where-Object { $_ -ne '' }

		return @($shares)
	}


        $syncProgress.CurrentIP = $server
        $syncProgress.IPs.Status = "Scanning $server..."
        $syncProgress.LogQueue.Enqueue(@{ Msg = "Scanning $server ..."; Color = "Cyan" })

        $shares = Get-ShareNames $server
        if (-not $shares) {
            $syncProgress.LogQueue.Enqueue(@{ Msg = "No shares found or access denied on $server"; Color = "Yellow" })
            return
        }

        $syncProgress.Shares[$server] = @{ Current = 0; Total = $shares.Count; Status = "Starting shares..." }

        foreach ($share in $shares) {
            $timestamp = (Get-Date -Format "MM/dd/yyyy HH:mm:ss")
            $searchPath = "\\$server\$share"
            $syncProgress.LogQueue.Enqueue(@{ Msg = "  Scanning $searchPath ..."; Color = "Cyan" })
            $syncProgress.Shares[$server].Current++
            $syncProgress.Shares[$server].Status = "Share $($syncProgress.Shares[$server].Current)/$($shares.Count) - $share"

            $fileKey = "$server\$share"
            $problems = @()
            $tempAllPaths = Get-AllFiles -RootPath $searchPath -ErrorList ([ref]$problems)
            if (-not $tempAllPaths) { $tempAllPaths = @() }

            $syncProgress.LogQueue.Enqueue(@{ Msg = "    $($tempAllPaths.Count) files found in $share"; Color = $null })
            $fileProgress[$fileKey] = @{ Total = $tempAllPaths.Count; FileName = "" }
            $fileCounter.TryAdd($fileKey, 0) | Out-Null

            $fileJobs = [System.Collections.Generic.List[object]]::new()

            foreach ($foundfile in $tempAllPaths) {
                $fileJobs.Add((Start-ThreadJob -Name "filejob_${share}_$($foundfile.Name)" -ThrottleLimit 4 -ArgumentList $foundfile, $server, $share, $timestamp, $fileKey, $fileCounter, $writeQueue, $keywordRegex, $fileExtensionSet, $tableName -ScriptBlock {

                    $file             = $args[0]
                    $server           = $args[1]
                    $share            = $args[2]
                    $timestamp        = $args[3]
                    $fileKey          = $args[4]
                    $fileCounter      = $args[5]
                    $writeQueue       = $args[6]
                    $keywordRegex     = $args[7]
                    $fileExtensionSet = $args[8]
                    $tableName        = $args[9]

                    try {
                        # ── 1. Filename keyword scan — single regex pass ───────
                        if ($file.FullName -match $keywordRegex) {
                            $nameMatches = ([regex]::Matches($file.FullName, $keywordRegex) |
                                ForEach-Object { $_.Value } | Select-Object -Unique) -join ","
                            $acl = try { Get-Acl $file.FullName } catch { $null }
                            $perms = if ($acl) { ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; " } else { "Error: permissions" }
                            $writeQueue.Enqueue(@{
                                Line   = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$nameMatches"",Keyword in filename"
                                Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($nameMatches -replace "'","''")','Keyword in filename');"
                            })
                        }

                        # ── 2. Extension check — O(1) HashSet lookup ───────────
                        if (-not $fileExtensionSet.Contains($file.Extension)) {
                            $writeQueue.Enqueue(@{
                                Line   = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: unsupported extension'"
                                Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: unsupported extension');"
                            })
                            return
                        }

                        # ── 3. Size check — skip if > 1GB ─────────────────────
                        if ($file.Length -gt 1GB) {
                            $writeQueue.Enqueue(@{
                                Line   = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: file > 1GB'"
                                Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: file > 1GB');"
                            })
                            return
                        }

                        # ── 4. Content keyword scan — single regex pass ────────
                        $content = Get-Content $file.FullName -Raw -Encoding utf8 -ErrorAction Stop
                        if ($content -match $keywordRegex) {
                            $contentMatches = ([regex]::Matches($content, $keywordRegex) |
                                ForEach-Object { $_.Value } | Select-Object -Unique) -join ","
                            $acl = try { Get-Acl $file.FullName } catch { $null }
                            $perms = if ($acl) { ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; " } else { "Error: permissions" }
                            $writeQueue.Enqueue(@{
                                Line   = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$contentMatches"","
                                Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($contentMatches -replace "'","''")','');"
                            })
                        }
                    }
                    catch {
                        $errPath = $file.FullName -replace "'", "''"
                        $errMsg  = $_.Exception.Message -replace "'", "''"
                        $writeQueue.Enqueue(@{
                            Line   = "$server,$share,,`'$errPath`',,$timestamp,,,,$errMsg"
                            Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','','$errPath','','$timestamp','','','','Error on Accessing');"
                        })
                    }

                    $fileCounter.AddOrUpdate($fileKey, 1, [Func[string, int, int]]{ param($k, $v) $v + 1 }) | Out-Null
                }))
            }

            # Wait for file jobs with a hard per-job timeout.
            # Track when each job was launched so we can kill any that exceed the limit.
            $fileJobStartTimes = @{}  # populated when job enters Running state, not at launch
            $fileJobNames      = @{}  # job.Id → filename for diagnostic logging
            $fileJobStopped    = @{}  # job.Id → $true once Stop-Job has been called
            foreach ($j in $fileJobs) { $fileJobNames[$j.Id] = $j.Name -replace '^filejob_[^_]+_','' }
            $fileJobHardTimeout = 120  # seconds a job may run before being force-stopped

            while ($true) {
                $pendingJobs = @($fileJobs | Where-Object { $_.State -in 'Running','NotStarted' })
                if (-not $pendingJobs) { break }
                $pendingJobs | Wait-Job -Timeout 10 | Out-Null

                $now = Get-Date

                # Record start time the first moment we see a job enter Running state
                foreach ($j in ($pendingJobs | Where-Object { $_.State -eq 'Running' })) {
                    if (-not $fileJobStartTimes.ContainsKey($j.Id)) {
                        $fileJobStartTimes[$j.Id] = $now
                    }
                }

                foreach ($j in ($pendingJobs | Where-Object { $_.State -eq 'Running' })) {
                    if ($fileJobStopped[$j.Id]) {
                        # Stop-Job already called but thread is stuck in kernel I/O and cannot be aborted.
                        # Log periodically so the user can see it is still blocking a slot.
                        $elapsed = [math]::Round(($now - $fileJobStartTimes[$j.Id]).TotalSeconds, 1)
                        if ($elapsed % 30 -lt 10) {
                            $syncProgress.LogQueue.Enqueue(@{ Msg = "    STUCK THREAD (slot lost): $($fileJobNames[$j.Id]) — ${elapsed}s, cannot abort SMB I/O — remaining jobs will still complete"; Color = "Red" })
                        }
                        continue
                    }

                    if ($fileJobStartTimes.ContainsKey($j.Id)) {
                        $elapsed = [math]::Round(($now - $fileJobStartTimes[$j.Id]).TotalSeconds, 1)
                        if ($elapsed -gt $fileJobHardTimeout) {
                            $hungFile = $fileJobNames[$j.Id]

                            # Drain error stream before killing
                            $jobErrors = $j | Receive-Job -ErrorAction SilentlyContinue 2>&1 |
                                Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                                ForEach-Object { $_.Exception.Message }
                            $errDetail = if ($jobErrors) { $jobErrors -join '; ' } else { "no error output captured" }

                            $syncProgress.LogQueue.Enqueue(@{ Msg = "    TIMEOUT: $hungFile hung for ${elapsed}s — $errDetail"; Color = "Red" })
                            $syncProgress.LogQueue.Enqueue(@{ Msg = "    NOTE: thread job cannot forcibly abort SMB I/O — slot may remain blocked until OS times out the connection"; Color = "Yellow" })
                            $j | Stop-Job
                            $fileJobStopped[$j.Id] = $true

                            $writeQueue.Enqueue(@{
                                Line   = "$server,$share,$hungFile,,'','$timestamp',,,,'Timeout after ${elapsed}s: $errDetail'"
                                Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($hungFile -replace "'","''")','','','$timestamp','','','','Timeout after ${elapsed}s: $($errDetail -replace "'","''")');"
                            })
                        }
                    }
                }
            }
            $fileJobs | Remove-Job -Force

            # Report enumeration errors
            foreach ($prob in $problems) {
                $errPath = $prob.TargetObject -replace "'", "''"
                $errMsg  = $prob.Message -replace "'", "''"
                $writeQueue.Enqueue(@{
                    Line   = "$server,$share,,`'$errPath`',,$timestamp,,,,$errMsg"
                    Insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','','$errPath','','$timestamp','','','','$errMsg');"
                })
            }

            # Clear file progress after share is done
            $null = $fileProgress.TryRemove($fileKey, [ref]$null)
            $null = $fileCounter.TryRemove($fileKey, [ref]$null)
        }

        $syncProgress.Shares.Remove($server)
        [System.Threading.Interlocked]::Increment([ref]$syncProgress.IPs.Current) | Out-Null
        $syncProgress.LogQueue.Enqueue(@{ Msg = "$server completed"; Color = "Green" })
    }))
}

# ────────────────────────────────────────────────────────────────
#   Wait until at least one job is actually running
# ────────────────────────────────────────────────────────────────

Write-Host "All jobs launched. Waiting for at least one to enter Running state..." -ForegroundColor Cyan

$timeoutSeconds = 15
$start = Get-Date
$runningFound = $false

while (((Get-Date) - $start).TotalSeconds -lt $timeoutSeconds) {
    $running = $ipJobs | Where-Object { $_.State -eq 'Running' }
    if ($running) {
        $runningFound = $true
        $syncProgress.LogQueue.Enqueue(@{ Msg = "Found $($running.Count) running jobs. Starting monitoring."; Color = "Green" })
        break
    }
    Start-Sleep -Milliseconds 500
}

if (-not $runningFound) {
    $syncProgress.LogQueue.Enqueue(@{ Msg = "No jobs entered Running state within $timeoutSeconds seconds. All jobs already completed or failed."; Color = "Red" })
    # You can add debugging here: $ipJobs | Format-List Name, State, Command, HasMoreData
}

# ────────────────────────────────────────────────────────────────
#   MAIN MONITORING LOOP
# ────────────────────────────────────────────────────────────────

$parentId = 10

try {
    while ($ipJobs | Where-Object { $_.State -in 'Running','NotStarted' }) {
        # ── Flush log queue ────────────────────────────────────────
        $logItem = $null
        while ($syncProgress.LogQueue.TryDequeue([ref]$logItem)) {
            if ($logItem.Color) { Write-Host $logItem.Msg -ForegroundColor $logItem.Color }
            else                { Write-Host $logItem.Msg }
        }

        # Bar 1: IPs
        $ip = $syncProgress.IPs
        $ipPct = if ($ip.Total -gt 0) { [math]::Round(($ip.Current / $ip.Total)*100, 1) } else { 0 }
        Write-Progress -Id $parentId `
                       -Activity "Scanning Network Shares" `
                       -Status "IP ($($ip.Current)/$($ip.Total)) $($ip.Status)" `
                       -PercentComplete $ipPct

        # Bar 2: Shares
        if ($syncProgress.CurrentIP -and $syncProgress.Shares.ContainsKey($syncProgress.CurrentIP)) {
            $sh = $syncProgress.Shares[$syncProgress.CurrentIP]
            Write-Progress -Id ($parentId + 1) `
                           -ParentId $parentId `
                           -Activity "Shares on $($syncProgress.CurrentIP)" `
                           -Status $sh.Status `
                           -PercentComplete ([math]::Round(($sh.Current / $sh.Total)*100, 1))
        }

        # Bar 3: Files — only show a share that has actually started (counter > 0)
        $activeKey = $fileProgress.Keys | Where-Object {
            $c = 0
            $fileCounter.TryGetValue($_, [ref]$c) | Out-Null
            $c -gt 0
        } | Select-Object -First 1

        if ($activeKey) {
            $f = $fileProgress[$activeKey]
            $currentCount = 0
            $fileCounter.TryGetValue($activeKey, [ref]$currentCount) | Out-Null
            $pct = if ($f.Total -gt 0) { [math]::Round(($currentCount / $f.Total) * 100, 1) } else { 0 }
            Write-Progress -Id ($parentId + 2) `
                           -ParentId ($parentId + 1) `
                           -Activity "Files in $activeKey" `
                           -Status "File $currentCount/$($f.Total)" `
                           -PercentComplete $pct
        } else {
            Write-Progress -Id ($parentId + 2) -ParentId ($parentId + 1) -Activity "Files" -Completed
        }

        Start-Sleep -Milliseconds 300
    }
}
finally {
    10..12 | ForEach-Object { Write-Progress -Id $_ -Completed }
}

# Cleanup — drain any remaining log queue entries then remove jobs
$ipJobs | Wait-Job -ErrorAction SilentlyContinue | Out-Null
$logItem = $null
while ($syncProgress.LogQueue.TryDequeue([ref]$logItem)) {
    if ($logItem.Color) { Write-Host $logItem.Msg -ForegroundColor $logItem.Color }
    else                { Write-Host $logItem.Msg }
}
$ipJobs | Remove-Job -Force -ErrorAction SilentlyContinue

# Signal the DB writer that no more inserts are coming, then wait for it to drain
$dbDone.Value = $true
$dbWriterJob | Wait-Job | Remove-Job -Force

Write-Host "`nScan completed." -ForegroundColor Green
Write-Host "Results saved to: $outputCsvFile"
Write-Host "Database:         $dbPath"
$elapsed = (Get-Date) - $scanStart
Write-Host "Time taken:       $('{0:D2}h {1:D2}m {2:D2}s' -f $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds)"
