<# 
    VaultNamespacesMounts.ps1
    This script lists all HashiCorp Vault namespaces (Vault 1.16.x) and for each namespace, retrieves all mount points – 
    both secret mounts (e.g. cubbyhole, kv, etc.) and auth mounts (e.g. aws, oidc, jwt, k8, approle, etc.). 
    For each mount point, it writes a record into a CSV file that includes the namespace, mount path, and mount type.

    The script:
      - Checks if a .vault-token file exists and uses its content if available.
      - If no token is found or if token authentication fails, securely prompts the user for a Vault token.
      - Prompts the user to choose a target environment with three URL options.
      - Queries the Vault API to list namespaces, secret mounts, and auth mounts.
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
Write-Host "1: https://prod.vaultserver.com"
Write-Host "2: https://dev.vaultserver.com"
Write-Host "3: https://test.vaultserver.com"
$envChoice = Read-Host "Enter option (1-3)"
switch ($envChoice) {
    "1" { $vaultUrl = "https://prod.vaultserver.com" }
    "2" { $vaultUrl = "https://int.vaultserver.com" }
    "3" { $vaultUrl = "https://test.vaultserver.com" }
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
    
    # Retrieve secret mounts
    $mountsUri = "$vaultUrl/v1/sys/mounts"
    try {
        $mountsResponse = Invoke-RestMethod -Method Get -Uri $mountsUri -Headers $nsHeaders -ErrorAction Stop
        if ($mountsResponse.data) {
            $mounts = $mountsResponse.data
        }
        else {
            $mounts = $mountsResponse
        }
        foreach ($mountProperty in $mounts.PSObject.Properties) {
            try {
                $mountPath = $mountProperty.Name.TrimEnd("/")
                $mountType = $mountProperty.Value.type
                Write-Host "Writing secret mount record - Namespace: $ns, Mount: $mountPath, Type: $mountType" -ForegroundColor Yellow
                $records += [pscustomobject]@{
                    Namespace = $ns
                    MountPath = $mountPath
                    MountType = $mountType
                }
            }
            catch {
                Write-Host "Error processing secret mount property '$($mountProperty.Name)': $_" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "Error retrieving secret mounts for namespace '$ns'. Error: $_" -ForegroundColor Red
    }

    # Retrieve auth mounts
    $authUri = "$vaultUrl/v1/sys/auth"
    try {
        $authResponse = Invoke-RestMethod -Method Get -Uri $authUri -Headers $nsHeaders -ErrorAction Stop
        if ($authResponse.data) {
            $authMounts = $authResponse.data
        }
        else {
            $authMounts = $authResponse
        }
        foreach ($authProperty in $authMounts.PSObject.Properties) {
            try {
                $mountPath = $authProperty.Name.TrimEnd("/")
                $mountType = $authProperty.Value.type
                Write-Host "Writing auth mount record - Namespace: $ns, Mount: $mountPath, Type: $mountType" -ForegroundColor Yellow
                $records += [pscustomobject]@{
                    Namespace = $ns
                    MountPath = $mountPath
                    MountType = $mountType
                }
            }
            catch {
                Write-Host "Error processing auth mount property '$($authProperty.Name)': $_" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "Error retrieving auth mounts for namespace '$ns'. Error: $_" -ForegroundColor Red
    }
}

# ----- Step 6: Export the Data to CSV -----
# Create a timestamp
$timestamp = Get-Date -Format "yyyyMMddHHmmss"

# Extract the hostname portion from the vaultUrl
$hostName = ([Uri]$vaultUrl).Host

# Construct output file name as {timestamp}-{target-url}-mounts.csv
$outputCsv = "$timestamp-$hostName-mounts.csv"
try {
    $records | Export-Csv -Path $outputCsv -NoTypeInformation -ErrorAction Stop
    Write-Host "CSV file generated: $outputCsv" -ForegroundColor Cyan
}
catch {
    Write-Host "Error exporting CSV file: $_" -ForegroundColor Red
}
