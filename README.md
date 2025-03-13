# Vault Namespaces and Mounts Exporter

This PowerShell script retrieves a list of namespaces and mount points from a HashiCorp Vault instance (Vault 1.16.x) and exports the details into a CSV file. It supports both token retrieval from a local file and interactive token input, and it allows you to select a target environment from predefined URL options.

## Features

- **Namespace Listing:**  
  Retrieves all available namespaces via the Vault API. If namespaces cannot be retrieved, it defaults to the root namespace.

- **Mount Points Retrieval:**  
  For each namespace, the script lists all mount points (including auth mounts and secrets mounts) along with their types (e.g., kv, jwt, approle, kubernetes, etc.).

- **Dynamic CSV Output:**  
  The output file is generated with a name in the format `{timestamp}-{target-url}-mounts.csv` (e.g., `20250313123045-prod.vaultserver.com-mounts.csv`).

- **Token Management:**  
  Checks for a `.vault-token` file and uses its content if available. If the file is missing or empty, the script securely prompts the user for a Vault token.

- **Target Environment Selection:**  
  Provides interactive selection of the target Vault environment from three options:
  - **1:** `https://prod.vaultserver.com`
  - **2:** `https://int.vaultserver.com`
  - **3:** `https://test.vaultserver.com`

## Prerequisites

- **HashiCorp Vault (Version 1.16.x):**  
  Ensure you have access to a Vault instance running version 1.16.x.

- **PowerShell:**  
  The script is designed to run on PowerShell (tested on both Windows PowerShell 5.x and PowerShell Core).

- **Vault Token:**  
  A valid Vault token is required. Store the token in a `.vault-token` file in the same directory as the script, or be ready to enter it when prompted.

## Usage

1. **Download the Script:**  
   Save the PowerShell script as `VaultNamespacesMounts.ps1`.

2. **Prepare Your Environment:**  
   Ensure that you have the necessary permissions to access the Vault instance and that your network settings allow connectivity.

3. **Run the Script:**  
   Open a PowerShell terminal, navigate to the script's directory, and execute:
   ```powershell
   .\VaultNamespacesMounts.ps1
