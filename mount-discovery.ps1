<# 
    VaultNamespacesMounts.ps1
    This script lists all HashiCorp Vault namespaces (Vault 1.16.x) and for each namespace, lists all mount points 
    (including auth mounts and secrets mounts). For each mount point, it writes a record into a CSV file that includes 
    the namespace, mount path, and mount type (e.g. kv, jwt, approle, kubernetes, etc).

    The script:
      - Checks if a .vault-token file exists and uses its content if available.
      - If no token is found or if token authentication fails, securely prompts the user for the token.
      - Prompts the user to choose a target environment with three URL options.
      - Queries the Vault API to list namespaces and mounts.
      - Exports the collected information to a timestamped CSV file named {timestamp}-{target-url}-mounts.csv.
#>

# Function: Convert SecureString to plain text
function Convert-SecureStringToPlainText {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

# ----- Step 1: Select Target Environment -----
Write-Host "Select target environment:" -ForegroundColor Cyan
Write-Host "1: https://prod.vault.company.com"
Write-Host "2: https://dev.vault.company.com"
Write-Host "3: https://test.vault.company.com"
$envChoice = Read-Host "Enter option (1-3)"
switch ($envChoice) {
    "1" { $vaultUrl = "https://prod.vault.company.com" }
    "2" { $vaultUrl = "https://dev.vault.company.com" }
    "3" { $vaultUrl = "ttps://test.vault.company.com" }
    default {
        Write-Host "Invalid option. Exiting." -ForegroundColor Red
        exit 1
    }
}

# ----- Step 2: Retrieve Vault Token -----
$tokenFile = ".vault-token"
if (Test-Path $tokenFile) {
    $vaultToken = Get-Content $tokenFile -Raw
    if ([string]::IsNullOrWhiteSpace($vaultToken)) {
        Write-Host "Token file exists but is empty."
        $secureToken = Read-Host "Enter Vault token" -AsSecureString
        $vaultToken = Convert-SecureStringToPlainText -SecureString $secureToken
    }
} else {
    $secureToken = Read-Host "Vault token not found. Enter Vault token" -AsSecureString
    $vaultToken = Convert-SecureStringToPlainText -SecureString $secureToken
}

# ----- Step 3: Validate the Token -----
$headers = @{ "X-Vault-Token" = $vaultToken }
$healthUri = "$vaultUrl/v1/sys/health"
try {
    # A health check can serve as a token validation
    $healthResponse = Invoke-RestMethod -Method Get -Uri $healthUri -Headers $headers -ErrorAction Stop
}
catch {
    Write-Host "Error authenticating with provided token. Please re-enter token." -ForegroundColor Yellow
    $secureToken = Read-Host "Enter Vault token" -AsSecureString
    $vaultToken = Convert-SecureStringToPlainText -SecureString $secureToken
    $headers["X-Vault-Token"] = $vaultToken
}

# ----- Step 4: Retrieve the List of Namespaces -----
$namespaceList = @()
$namespacesUri = "$vaultUrl/v1/sys/namespaces?list=true"
try {
    $nsResponse = Invoke-RestMethod -Method Get -Uri $namespacesUri -Headers $headers -ErrorAction Stop
    if ($nsResponse.data -and $nsResponse.data.keys) {
        $namespaceList = $nsResponse.data.keys
    }
    else {
        Write-Host "No namespaces returned from API." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error retrieving namespaces. Assuming only the root namespace exists." -ForegroundColor Yellow
}

# Always include the root namespace (represented as "root" here)
if (-not ($namespaceList -contains "root")) {
    $namespaceList += "root"
}

# ----- Step 5: Retrieve Mounts for Each Namespace -----
$records = @()
foreach ($ns in $namespaceList) {
    Write-Host "Processing namespace: $ns" -ForegroundColor Green
    # Setup headers – if not the root namespace, add the X-Vault-Namespace header.
    $nsHeaders = @{ "X-Vault-Token" = $vaultToken }
    if ($ns -and $ns -ne "root") {
        $nsHeaders["X-Vault-Namespace"] = $ns
    }
    $mountsUri = "$vaultUrl/v1/sys/mounts"
    try {
        $mountsResponse = Invoke-RestMethod -Method Get -Uri $mountsUri -Headers $nsHeaders -ErrorAction Stop
        # The response is a hashtable; each key is a mount path and the value contains details.
        foreach ($mountProperty in $mountsResponse.PSObject.Properties) {
            $mountPath = $mountProperty.Name.TrimEnd("/")
            $mountType = $mountProperty.Value.type
            $records += [pscustomobject]@{
                Namespace = $ns
                MountPath = $mountPath
                MountType = $mountType
            }
        }
    }
    catch {
        Write-Host "Error retrieving mounts for namespace: $ns" -ForegroundColor Red
    }
}

# ----- Step 6: Export the Data to CSV -----
# Create a timestamp
$timestamp = Get-Date -Format "yyyyMMddHHmmss"

# Extract the hostname portion from the vaultUrl
$hostName = ([Uri]$vaultUrl).Host

# Construct output file name as {timestamp}-{target-url}-mounts.csv
$outputCsv = "$timestamp-$hostName-mounts.csv"
$records | Export-Csv -Path $outputCsv -NoTypeInformation
Write-Host "CSV file generated: $outputCsv" -ForegroundColor Cyan
