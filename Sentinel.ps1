# ---------- SETTINGS ----------
$rg  = "1332-e5749246-investigate-a-security-incident-usin"
$ws  = "security-logs"
$path = "$HOME/Sentinel.json"

$logType = "Security_Logs"   # -> Security_Logs_CL
$batchSize = 200             # keep requests reasonably sized

# ---------- GET WORKSPACE ID + KEY ----------
$customerId = az monitor log-analytics workspace show -g $rg -n $ws --query customerId -o tsv
$sharedKey  = az monitor log-analytics workspace get-shared-keys -g $rg -n $ws --query primarySharedKey -o tsv

if (-not (Test-Path $path)) {
  throw "File not found: $path. Upload Sentinel.json to Cloud Shell first."
}

# ---------- READ + PARSE JSON ----------
$content = Get-Content -Raw -Path $path
$trim = $content.TrimStart()
$payloadObjects = @()

if ($trim.StartsWith("[")) {
  $payloadObjects = @($content | ConvertFrom-Json)
} elseif ($trim.StartsWith("{")) {
  $payloadObjects = @(
    $content -split "`n" |
      Where-Object { $_.Trim() -ne "" } |
      ForEach-Object { $_ | ConvertFrom-Json }
  )
} else {
  throw "Unrecognized JSON format in $path. Expected JSON array or NDJSON."
}

if ($payloadObjects.Count -eq 0) { throw "No records found in Sentinel.json" }

# ---------- NORMALIZE TimeGenerated to ISO 8601 UTC ----------
# Handles:
# - DateTime objects (what you're seeing)
# - strings like "2/1/2026 6:00:01 PM"
foreach ($o in $payloadObjects) {
  if (-not $o.PSObject.Properties["TimeGenerated"]) {
    # If missing, set to now (UTC)
    $o | Add-Member -NotePropertyName TimeGenerated -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o") -Force
    continue
  }

  $tg = $o.TimeGenerated

  # If it's already a DateTime (your case), force UTC ISO
  if ($tg -is [DateTime]) {
    $o.TimeGenerated = ($tg.ToUniversalTime().ToString("o"))
    continue
  }

  # If it's a string, try parse then convert
  if ($tg -is [string]) {
    $dt = $null
    if ([DateTime]::TryParse($tg, [ref]$dt)) {
      $o.TimeGenerated = ($dt.ToUniversalTime().ToString("o"))
    } else {
      # If it doesn't parse, set to now to avoid drops
      $o.TimeGenerated = (Get-Date).ToUniversalTime().ToString("o")
    }
  }
}

Write-Host "Parsed $($payloadObjects.Count) records from $path"
Write-Host "First record (after normalization):"
$payloadObjects[0] | Format-List | Out-String | Write-Host

# ---------- HELPER: SIGN + POST ONE BATCH ----------
function Send-LogBatch {
  param(
    [Parameter(Mandatory=$true)][object[]]$Batch,
    [Parameter(Mandatory=$true)][string]$CustomerId,
    [Parameter(Mandatory=$true)][string]$SharedKey,
    [Parameter(Mandatory=$true)][string]$LogType
  )

  $body = ($Batch | ConvertTo-Json -Depth 20)
  $method = "POST"
  $contentType = "application/json"
  $resource = "/api/logs"
  $rfc1123date = (Get-Date).ToUniversalTime().ToString("r")
  $contentLength = ([System.Text.Encoding]::UTF8.GetByteCount($body))

  $stringToHash = "$method`n$contentLength`n$contentType`n" + "x-ms-date:$rfc1123date`n$resource"
  $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
  $keyBytes = [Convert]::FromBase64String($SharedKey)

  $sha256 = New-Object System.Security.Cryptography.HMACSHA256
  $sha256.Key = $keyBytes
  $calculatedHash = $sha256.ComputeHash($bytesToHash)
  $encodedHash = [Convert]::ToBase64String($calculatedHash)

  $signature = "SharedKey ${CustomerId}:${encodedHash}"
  $uri = "https://${CustomerId}.ods.opinsights.azure.com${resource}?api-version=2016-04-01"

  $headers = @{
    "Authorization"        = $signature
    "Log-Type"             = $LogType
    "x-ms-date"            = $rfc1123date
    "time-generated-field" = "TimeGenerated"
  }

  Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body | Out-Null
}

# ---------- SEND IN BATCHES ----------
for ($i = 0; $i -lt $payloadObjects.Count; $i += $batchSize) {
  $end = [Math]::Min($i + $batchSize, $payloadObjects.Count)
  $batch = $payloadObjects[$i..($end - 1)]
  Write-Host "Sending records $i .. $($end - 1) to ${logType}_CL ..."
  Send-LogBatch -Batch $batch -CustomerId $customerId -SharedKey $sharedKey -LogType $logType
}

Write-Host "Done. Sent $($payloadObjects.Count) records to ${logType}_CL."

