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

$lock = [System.Object]::new()

$servers = Get-Content $serverList -ErrorAction Stop
$syncProgress.IPs.Total = $servers.Count

$ipJobs = @()


# ────────────────────────────────────────────────────────────────
#   MAIN LOOP - Launch one thread job per IP
# ────────────────────────────────────────────────────────────────

foreach ($server in $servers) {
    $ipJobs += Start-ThreadJob -ThrottleLimit $throttle -ArgumentList $server, $fileCounter, $fileProgress -ScriptBlock {

        $server          = $args[0]
        $fileCounter     = $args[1]   # ConcurrentDictionary[string,int] — atomic int counter, survives serialization
        $fileProgress    = $args[2]   # ConcurrentDictionary[string,hashtable] — safe for cross-thread key enumeration
        $syncProgress    = $using:syncProgress
        $keywords        = $using:keywords
        $fileExtensions  = $using:fileExtensions
        $outputCsvFile   = $using:outputCsvFile
        $dbPath          = $using:dbPath
        $tableName       = $using:tableName
        $lock            = $using:lock

        # Update IP progress now that this job is actually running
        $syncProgress.IPs.Current++
        $syncProgress.IPs.Status = "Processing $server ($($syncProgress.IPs.Current)/$($syncProgress.IPs.Total))"
        $syncProgress.CurrentIP  = $server
    # ────────────────────────────────────────────────────────────────
    #   FUNCTION: Enumerate files (with batch parallel processing)
    # ────────────────────────────────────────────────────────────────

	function Get-AllFiles {
		[CmdletBinding()]
		param(
			[Parameter(Mandatory)]
			[string]$RootPath,

			[int]$ThrottleLimit = 8,

			[int]$BatchSize = 10000,

			[ref]$ErrorList  # User supplies: -ErrorList ([ref]$problems)
		)

		#$enumerator = [System.IO.Directory]::EnumerateFiles($RootPath, '*', 'AllDirectories').GetEnumerator()
		$results = @()
		$batch = @()

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
		}

		while ($enumerator.MoveNext()) {
			$batch += $enumerator.Current
			if ($batch.Count -ge $BatchSize) {
				$results += $batch | ForEach-Object -Parallel {
					param()
					$path = $_

					try {
						$f = [System.IO.FileInfo]::new($path)
						[PSCustomObject]@{
							Name         = $f.Name
							FullName     = $f.FullName
							Length       = $f.Length
							Extension    = $f.Extension
							CreationTime = $f.CreationTime
						}
					} catch {
						# Gather error details in a buffer for this batch/job instance
						$err = @{
							TargetObject = $path
							Exception = $_.Exception
							Message = $_.Exception.Message
						}
						# Instead of trying to access [ref] variable (not possible directly),
						# output error with a property marker for handling in parent scope:
						[PSCustomObject]@{__IsError = $true; Data = $err}
					}
				} -ThrottleLimit $ThrottleLimit

				$batch = @()
			}
		}
		if ($batch.Count -gt 0) {
			$results += $batch | ForEach-Object -Parallel {
				param()
				$path = $_
				
				try {
					$f = [System.IO.FileInfo]::new($path)
					[PSCustomObject]@{
						Name         = $f.Name
						FullName     = $f.FullName
						Length       = $f.Length
						Extension    = $f.Extension
						CreationTime = $f.CreationTime
					}
				} catch {
					$err = @{
						TargetObject = $path
						Exception = $_.Exception
						Message = $_.Exception.Message
					}
					[PSCustomObject]@{__IsError = $true; Data = $err}
				}
			} -ThrottleLimit $ThrottleLimit
		}

		# Process output, split errors to the error list
		foreach ($item in $results) {
			if ($item -is [PSObject] -and $item.PSObject.Properties['__IsError']) {
				if ($null -ne $ErrorList) { $ErrorList.Value += $item.Data }
			} else {
				# Output only the actual files
				$item
			}
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

            $syncProgress.LogQueue.Enqueue(@{ Msg = "    $($tempAllPaths.Count) files found in $share"; Color = $null })
            $fileProgress[$fileKey] = @{ Total = $tempAllPaths.Count; FileName = "" }
            $fileCounter[$fileKey] = 0

            $fileJobs = @()

            foreach ($foundfile in $tempAllPaths) {
                $fileJobs += Start-ThreadJob -ThrottleLimit 4 -ArgumentList $foundfile, $server, $share, $timestamp, $fileKey, $fileCounter, $syncProgress, $lock, $keywords, $fileExtensions, $outputCsvFile, $dbPath, $tableName -ScriptBlock {

                    $file           = $args[0]
                    $server         = $args[1]
                    $share          = $args[2]
                    $timestamp      = $args[3]
                    $fileKey        = $args[4]
                    $fileCounter    = $args[5]   # ConcurrentDictionary[string,int] — atomic int, survives serialization
                    $syncProgress   = $args[6]
                    $lock           = $args[7]
                    $keywords       = $args[8]
                    $fileExtensions = $args[9]
                    $outputCsvFile  = $args[10]
                    $dbPath         = $args[11]
                    $tableName      = $args[12]

                    $syncProgress.LogQueue.Enqueue(@{ Msg = "    Scanning $($file.FullName)..."; Color = "Cyan" })
                    try {
                        # ── Collect all filename keyword matches (no early exit) ──
                        $nameMatches = @($keywords.Where{ $file.FullName -match [regex]::Escape($_) })

                        # ── Skip unsupported extensions ────────────────────────
                        # If filename matched, still record it — just skip content scan.
                        if ($fileExtensions -notcontains $file.Extension) {
                            if ($nameMatches.Count -gt 0) {
                                $acl = try { Get-Acl $file.FullName } catch { $null }
                                $perms = if ($acl) { ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; " } else { "Error: permissions" }
                                $foundStr = $nameMatches -join ","
                                $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"",Keyword in filename"
                                $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','Keyword in filename');"
                                [System.Threading.Monitor]::Enter($lock)
                                try {
                                    $line | Out-File $outputCsvFile -Append -Encoding utf8
                                    $insert | sqlite3 $dbPath
                                } finally { [System.Threading.Monitor]::Exit($lock) }
                            } else {
                                $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: unsupported extension'"
                                $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: unsupported extension');"
                                [System.Threading.Monitor]::Enter($lock)
                                try {
                                    $line | Out-File $outputCsvFile -Append -Encoding utf8
                                    $insert | sqlite3 $dbPath
                                } finally { [System.Threading.Monitor]::Exit($lock) }
                            }
                            return
                        }

                        # ── Skip very large files ──────────────────────────────
                        if ($file.Length -gt 1GB) {
                            if ($nameMatches.Count -gt 0) {
                                $acl = try { Get-Acl $file.FullName } catch { $null }
                                $perms = if ($acl) { ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; " } else { "Error: permissions" }
                                $foundStr = $nameMatches -join ","
                                $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"",Keyword in filename - file > 1GB not content scanned"
                                $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','Keyword in filename - file > 1GB not content scanned');"
                                [System.Threading.Monitor]::Enter($lock)
                                try {
                                    $line | Out-File $outputCsvFile -Append -Encoding utf8
                                    $insert | sqlite3 $dbPath
                                } finally { [System.Threading.Monitor]::Exit($lock) }
                            } else {
                                $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),,,'Skipped: file > 1GB'"
                                $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','','','Skipped: file > 1GB');"
                                [System.Threading.Monitor]::Enter($lock)
                                try {
                                    $line | Out-File $outputCsvFile -Append -Encoding utf8
                                    $insert | sqlite3 $dbPath
                                } finally { [System.Threading.Monitor]::Exit($lock) }
                            }
                            return
                        }

                        # ── Read content and search ────────────────────────────
                        $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                        $contentMatches = @($keywords.Where{ $content -match [regex]::Escape($_) })

                        # ACL fetched once if either match type fires
                        if ($nameMatches.Count -gt 0 -or $contentMatches.Count -gt 0) {
                            $acl = try { Get-Acl $file.FullName } catch { $null }
                            $perms = if ($acl) { ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; " } else { "Error: permissions" }
                        }

                        # ── Row 1: filename match ──────────────────────────────
                        if ($nameMatches.Count -gt 0) {
                            $foundStr = $nameMatches -join ","
                            $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"",Keyword in filename"
                            $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','Keyword in filename');"
                            [System.Threading.Monitor]::Enter($lock)
                            try {
                                $line | Out-File $outputCsvFile -Append -Encoding utf8
                                $insert | sqlite3 $dbPath
                            } finally { [System.Threading.Monitor]::Exit($lock) }
                        }

                        # ── Row 2: content match ───────────────────────────────
                        if ($contentMatches.Count -gt 0) {
                            $foundStr = $contentMatches -join ","
                            $line = "$server,$share,$($file.Name),$($file.FullName),$($file.CreationTime),$timestamp,$($file.Length),""$perms"",""$foundStr"","
                            $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','$($file.Name -replace "'","''")',`'$($file.FullName -replace "'","''")`','$($file.CreationTime)','$timestamp','$($file.Length)','$($perms -replace "'","''")','$($foundStr -replace "'","''")','');"
                            [System.Threading.Monitor]::Enter($lock)
                            try {
                                $line | Out-File $outputCsvFile -Append -Encoding utf8
                                $insert | sqlite3 $dbPath
                            } finally { [System.Threading.Monitor]::Exit($lock) }
                        }
                    }
                    catch {
                        $errPath  = $file.FullName -replace "'", "''"
                        $errMsg   = $_.Exception.Message -replace "'", "''"
                        $line = "$server,$share,,`'$errPath`',,$timestamp,,,,$errMsg"
                        $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','','$errPath','','$timestamp','','','','Error on Accessing');"

                        [System.Threading.Monitor]::Enter($lock)
                        try {
                            $line | Out-File $outputCsvFile -Append -Encoding utf8
                            $insert | sqlite3 $dbPath
                        } finally { [System.Threading.Monitor]::Exit($lock) }
                    }

                    # ── Update file progress ──────────────────────────────────
                    # fileCounter holds int values — AddOrUpdate on int is truly atomic across thread boundaries.
                    $fileCounter.AddOrUpdate($fileKey, 1, [Func[string, int, int]]{ param($k, $v) $v + 1 }) | Out-Null
                }
            }

            # Wait for all file jobs in this share
            $fileJobs | Wait-Job | Remove-Job -Force

            # Report enumeration errors
            foreach ($prob in $problems) {
                $errPath = $prob.TargetObject -replace "'", "''"
                $errMsg  = $prob.Message -replace "'", "''"
                $line = "$server,$share,,`'$errPath`',,$timestamp,,,,$errMsg"
                $insert = "INSERT INTO $tableName (IP,ShareName,FileName,FilePath,CreationTime,TimeStamp,Size,Permissions,TriggerKeyword,Error) VALUES ('$server','$share','','$errPath','','$timestamp','','','','$errMsg');"

                [System.Threading.Monitor]::Enter($lock)
                try {
                    $line | Out-File $outputCsvFile -Append -Encoding utf8
                    $insert | sqlite3 $dbPath
                } finally { [System.Threading.Monitor]::Exit($lock) }
            }

            # Clear file progress after share is done
            $null = $fileProgress.TryRemove($fileKey, [ref]$null)
            $null = $fileCounter.TryRemove($fileKey, [ref]$null)
        }

        # Clear share progress after IP is done
        $syncProgress.Shares.Remove($server)
        $syncProgress.LogQueue.Enqueue(@{ Msg = "$server completed"; Color = "Green" })
    }
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
    while ($ipJobs | Where-Object { $_.State -eq 'Running' }) {
        # ── Flush buffered Write-Host output from all jobs in real time ──
        # Receive-Job (without -AutoRemoveJob) drains pending output each tick,
        # preserving Write-Host colors. PowerShell renders it above the progress bars.
        # Drain the log queue — real-time Write-Host from all thread jobs
        $logItem = $null
        while ($syncProgress.LogQueue.TryDequeue([ref]$logItem)) {
            if ($logItem.Color) { Write-Host $logItem.Msg -ForegroundColor $logItem.Color }
            else                { Write-Host $logItem.Msg }
        }

        # Bar 1: IPs
        $ip = $syncProgress.IPs
        Write-Progress -Id $parentId `
                       -Activity "Scanning Network Shares" `
                       -Status "IP $($ip.Current)/$($ip.Total) - $($ip.Status)" `
                       -PercentComplete ([math]::Round(($ip.Current / $ip.Total)*100, 1))

        # Bar 2: Shares
        if ($syncProgress.CurrentIP -and $syncProgress.Shares.ContainsKey($syncProgress.CurrentIP)) {
            $sh = $syncProgress.Shares[$syncProgress.CurrentIP]
            Write-Progress -Id ($parentId + 1) `
                           -ParentId $parentId `
                           -Activity "Shares on $($syncProgress.CurrentIP)" `
                           -Status $sh.Status `
                           -PercentComplete ([math]::Round(($sh.Current / $sh.Total)*100, 1))
        }

        # Bar 3: Files
        $activeKey = $fileProgress.Keys | Where-Object { $fileProgress[$_].Total -gt 0 } | Select-Object -First 1
        if ($activeKey) {
            $f = $fileProgress[$activeKey]
            $shareName = $activeKey.Split('\')[1]
            $currentCount = 0
            $fileCounter.TryGetValue($activeKey, [ref]$currentCount) | Out-Null
            $pct = if ($f.Total -gt 0) { [math]::Round(($currentCount / $f.Total) * 100, 1) } else { 0 }
            Write-Progress -Id ($parentId + 2) `
                           -ParentId ($parentId + 1) `
                           -Activity "Files in $shareName" `
                           -Status "File $currentCount/$($f.Total)$(if ($f.FileName) { ' - ' + $f.FileName })" `
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

Write-Host "`nScan completed." -ForegroundColor Green
Write-Host "Results saved to: $outputCsvFile"
Write-Host "Database:         $dbPath"
