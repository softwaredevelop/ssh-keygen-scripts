function Get-HelloWorld {
    <#
.SYNOPSIS
This function returns the string "Hello World".

.DESCRIPTION
The Get-HelloWorld function is a simple function that outputs the string "Hello World".

.EXAMPLE
Get-HelloWorld
Outputs: "Hello World"
#>
    Write-Output "Hello World"
}
Export-ModuleMember -Function "Get-HelloWorld"

function Get-InternalHelloWorld {
    <#
.SYNOPSIS
    Retrieves the internal "Hello World" message.

.DESCRIPTION
    The Get-InternalHelloWorld function returns the "Internal Hello World" message.

.EXAMPLE
    Get-InternalHelloWorld
    # Output: Internal Hello World
#>
    Write-Output "Internal Hello World"
}

function Test-IsWindowsAdmin {
    <#
.SYNOPSIS
Checks if the current user is running the script as a Windows Administrator.

.DESCRIPTION
The Test-IsWindowsAdmin function checks if the current user has administrative privileges on a Windows system.

.PARAMETER None
This function does not accept any parameters.

.EXAMPLE
Test-IsWindowsAdmin
Checks if the current user is a Windows Administrator.

.OUTPUTS
System.Boolean
Returns $true if the current user is a Windows Administrator, otherwise returns $false.
#>
    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Start-ServiceWithRetry {
    <#
.SYNOPSIS
    Starts a service with retry attempts.

.DESCRIPTION
    The Start-ServiceWithRetry function starts a specified service and retries if it fails to start.
    It checks if the script is run with administrator privileges and then attempts to start the service.
    If the service fails to start, it waits for 5 seconds and retries a maximum of 5 times.

.PARAMETER ServiceName
    The name of the service to start.

.PARAMETER MaxRetries
    The maximum number of retry attempts. Default is 5.

.EXAMPLE
    Start-ServiceWithRetry -ServiceName "MTProxyService.exe"
    Starts the service named "MTProxyService.exe" with default retry attempts.

.EXAMPLE
    Start-ServiceWithRetry -ServiceName "MTProxyService.exe" -MaxRetries 10
    Starts the service named "MTProxyService.exe" with 10 retry attempts.
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [int]$MaxRetries = 5
    )

    if (-not (Test-IsWindowsAdmin)) {
        Write-Error "This script must be run with administrator privileges."
        Break
    }

    $service = Get-Service -Name $ServiceName
    $retryCount = 0

    while ($service.Status -ne 'Running' -and $retryCount -lt $MaxRetries) {
        try {
            Set-Service -Name $ServiceName -Status Running -ErrorAction Stop
        } catch {
            Write-Output "Failed to start service. Retrying in 5 seconds..."
            Start-Sleep -Seconds 5
            $retryCount++
        } finally {
            $service = Get-Service -Name $ServiceName
        }
    }

    if ($service.Status -eq 'Running') {
        Write-Output "Service is now running."
    } else {
        Write-Output "Failed to start service after $MaxRetries attempts."
    }
}
Export-ModuleMember -Function "Start-ServiceWithRetry"

function Update-System {
    <#
.SYNOPSIS
    Updates the system by installing Windows updates.

.DESCRIPTION
    The Update-System function is used to update the system by installing Windows updates. It checks if the script is run with administrator privileges and then retrieves the available updates using the Get-WindowsUpdate cmdlet. If there are updates available, it installs them using the Install-WindowsUpdate cmdlet.

.PARAMETER Update
    Specifies the type of updates to install. Valid values are "WindowsUpdate" and "MicrosoftUpdate". The default value is "WindowsUpdate".

.EXAMPLE
    Update-System -Update "WindowsUpdate"
    Updates the system by installing Windows updates.

.EXAMPLE
    Update-System -Update "MicrosoftUpdate"
    Updates the system by installing Microsoft updates.
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [string]$Update = "WindowsUpdate"
    )

    if (-not (Test-IsWindowsAdmin)) {
        Write-Error -Message "Error: This script must be run with administrator privileges." -ErrorId "NotAdmin"
        Break
    }

    $commandParameters = @{
        Verbose = $true
    }
    if ($Update -eq "WindowsUpdate" -or $Update -eq "MicrosoftUpdate") {
        $commandParameters[$Update] = $true
    }
    $parameters = @{
        ScriptBlock = { Get-WindowsUpdate @commandParameters }
    }
    $updates = Invoke-Command @parameters

    if ($updates.Count -gt 0) {
        $commandParameters = @{
            Verbose      = $true
            AcceptAll    = $true
            IgnoreReboot = $true
        }
        if ($Update -eq "WindowsUpdate" -or $Update -eq "MicrosoftUpdate") {
            $commandParameters[$Update] = $true
        }
        $parameters = @{
            ScriptBlock = { Install-WindowsUpdate @commandParameters }
        }
        Invoke-Command @parameters
    } else {
        Write-Output "No updates available for ${Update}."
    }
}
Export-ModuleMember -Function "Update-System"

function Install-WindowsGsudo {
    <#
.SYNOPSIS
Installs the Windows version of gsudo if it is not already installed.

.DESCRIPTION
The Install-WindowsGsudo function installs the Windows version of gsudo if it is not already installed. It checks if the specified gsudoPath exists, and if not, it uses the 'winget' command to install gsudo.

.PARAMETER gsudoPath
The path to the gsudo executable.

.EXAMPLE
Install-WindowsGsudo -gsudoPath "C:\Program Files\gsudo\gsudo.exe"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$gsudoPath
    )
    if (-not (Test-Path $gsudoPath)) {
        winget install --id=gerardog.gsudo
    }
}

function Install-WindowsOpenSSHClient {
    <#
.SYNOPSIS
Installs the Windows OpenSSH client.

.DESCRIPTION
This function installs the Windows OpenSSH client if it is not already installed. It checks if the specified SSH path exists, and if not, it adds the OpenSSH client capability to the Windows system.

.PARAMETER SshPath
The path to the SSH executable.

.EXAMPLE
Install-WindowsOpenSSHClient -SshPath "C:\OpenSSH\ssh.exe"
Installs the Windows OpenSSH client using the specified SSH path.

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SshPath
    )
    if (-not (Test-Path $SshPath)) {
        if ((Test-IsWindowsAdmin) -eq $false) {
            Invoke-Gsudo {
                Add-WindowsCapability -Online -Name OpenSSH.Client~~~~
            }
        } else {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~
        }
    }
}

function Install-WindowsNmap {
    <#
.SYNOPSIS
Installs Windows Nmap if it is not already installed.

.DESCRIPTION
The Install-WindowsNmap function installs Windows Nmap if it is not already installed on the system. It checks if the specified ncatPath exists, and if not, it uses the 'winget' command to install the Insecure.Nmap package.

.PARAMETER ncatPath
The path to the ncat executable.

.EXAMPLE
Install-WindowsNmap -ncatPath "C:\Program Files\Nmap\ncat.exe"
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ncatPath
    )
    if (-not (Test-Path $ncatPath)) {
        winget install --id=Insecure.Nmap
    }
}

function New-DirectoryIfNotExist {
    <#
.SYNOPSIS
Creates a new directory if it does not already exist.

.DESCRIPTION
The New-DirectoryIfNotExist function creates a new directory at the specified path if it does not already exist. If the directory already exists, it returns the existing directory.

.PARAMETER Path
The path where the new directory should be created.

.PARAMETER ChildPath
An optional child path to append to the parent path.

.EXAMPLE
New-DirectoryIfNotExist -Path "C:\Temp" -ChildPath "Subfolder"
Creates a new directory at "C:\Temp\Subfolder" if it does not already exist.

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$ChildPath = ""
    )

    $fullPath = Join-Path -Path $Path -ChildPath $ChildPath

    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Force -Path $fullPath
    } else {
        Get-Item -Path $fullPath
    }
}

function Set-Permission {
    <#
.SYNOPSIS
Sets permissions for a specified item.

.DESCRIPTION
The Set-Permission function is used to set permissions for a specified item in the file system. It removes all existing access rules for the item and adds a new access rule based on the provided parameters.

.PARAMETER Item
The path of the item for which permissions need to be set.

.PARAMETER IdentityReference
The identity reference for the user or group to which the permissions will be applied.

.PARAMETER FileSystemRights
The file system rights to be granted to the user or group.

.PARAMETER AccessControlType
The type of access control to be applied.

.EXAMPLE
Set-Permission -Item "C:\Path\To\File.txt" -IdentityReference "DOMAIN\Username" -FileSystemRights "Read" -AccessControlType "Allow"
Sets read permissions for the user "DOMAIN\Username" on the file "C:\Path\To\File.txt".
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Item,

        [Parameter(Mandatory = $true)]
        [string]$IdentityReference,

        [Parameter(Mandatory = $true)]
        [string]$FileSystemRights,

        [Parameter(Mandatory = $true)]
        [string]$AccessControlType
    )

    $acl = Get-Acl -Path $Item
    foreach ($accessRule in $acl.Access) {
        $acl.RemoveAccessRule($accessRule)
    }
    $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($IdentityReference, $FileSystemRights, $AccessControlType)
    $acl.AddAccessRule($accessRule)
    Set-Acl -Path $Item -AclObject $acl
}

function Set-SSHKeyPasswordProtected {
    <#
.SYNOPSIS
Generates a password-protected SSH key for a remote host.

.DESCRIPTION
The Set-SSHKeyPasswordProtected function generates a password-protected SSH key for a specified remote host. It supports different key types such as RSA, ECDSA, and Ed25519. The function installs necessary dependencies, creates the required directories, sets permissions, and generates the SSH key with the specified parameters.

.PARAMETER RemoteHost
The hostname or IP address of the remote host. The default value is "github.com".

.PARAMETER RemoteUser
The username for the remote host. The default value is "githubuser".

.PARAMETER Keytype
The type of SSH key to generate. Valid values are "rsa", "ecdsa", and "ed25519". The default value is "ed25519".

.PARAMETER Comment
The comment to include in the SSH key. If not specified, it will be set to "RemoteUser@RemoteHost".

.EXAMPLE
Set-SSHKeyPasswordProtected -RemoteHost "example.com" -RemoteUser "user" -Keytype "rsa" -Comment "My RSA Key"
Generates an RSA SSH key with the specified parameters for the remote host "example.com" and the username "user". The comment for the key is set to "My RSA Key".

.NOTES
This function requires administrative privileges on Windows to install dependencies and set permissions.
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$RemoteHost = "github.com",
        [string]$RemoteUser = "githubuser",
        [string]$Keytype = "ed25519",
        [string]$Comment
    )

    if (-not $Comment) {
        $Comment = "$RemoteUser@$RemoteHost"
    }

    $rsaKeylength = 4096
    $ecdsaKeylength = 521

    $Kdf = Get-Random -Minimum 16 -Maximum 27

    if ($Keytype -eq "rsa") {
        $Id = "id_rsa_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-b$rsaKeylength", "-C$Comment")
    } elseif ($Keytype -eq "ecdsa") {
        $Id = "id_ecdsa_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-b$ecdsaKeylength", "-C$Comment")
    } elseif ($Keytype -eq "ed25519") {
        $Id = "id_ed25519_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-C$Comment")
    }

    if (
        $PSVersionTable.Platform -eq 'Win32NT' -or
        [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or
        $null -eq $PSVersionTable.Platform
    ) {
        # We are on Windows
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Define the path to the winget executable
        $wingetPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
        # Check if winget is installed
        if (-not (Test-Path $wingetPath)) {
            # Winget is not installed, exit the script
            Write-Error "Winget is not installed."
            Break
        }

        # Install gsudo if not already installed
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Install-WindowsGsudo -gsudoPath $gsudoPath

        # Install openssh client if not already installed
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        Install-WindowsOpenSSHClient -SshPath $sshPath

        # Install Nmap if not already installed
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        Install-WindowsNmap -ncatPath $ncatPath

        # Create .ssh directory if not already exists
        $sshDirPath = New-DirectoryIfNotExist -Path $([Environment]::GetFolderPath("USERPROFILE")) -ChildPath ".ssh"

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwDirPath = New-DirectoryIfNotExist -Path $sshDirPath.FullName -ChildPath ".pw"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permission -Item $sshDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permission -Item $pwDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

        # Generate a random password for SSH
        $sshPass = ConvertTo-SecureString -String $( -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })) -AsPlainText -Force

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $chars = @(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z'
        )
        $hash = -join (1..6 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $keyName = "$RemoteHost.$RemoteUser" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath.FullName) -and (Test-Path -Path $pwDirPath.FullName)) {
            # Check if sshPass and keyName are not null
            if ($null -ne $sshPass -and $null -ne $keyName) {
                $pwFilePath = Join-Path -Path $pwDirPath.FullName -ChildPath "pw_$keyName"

                # Write sshPass to pw file
                $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sshPass)
                Set-Content -Path $pwFilePath -Value $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pointer))
                # Set $pwFilePath permission to 400
                Set-Permission -Item $pwFilePath -IdentityReference $env:USERNAME -FileSystemRights "Read" -AccessControlType "Allow"

                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath.FullName -ChildPath "$Id$keyName.key"
                ssh-keygen $keyOptions -f $keyfile -N $sshPass
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                if ((Test-IsAdminWindows) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path $using:keyfile -AclObject $using:keyfileAcl
                        # Set-Permission -Item $using:keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
                    # Set-Permission -Item $keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                }

                # Set "$keyfile.pub" permissions to 644
                # Get the existing ACL
                $keyfilePubAcl = Get-Acl -Path "$keyfile.pub"
                # Remove all existing access rules
                foreach ($accessRule in $keyfilePubAcl.Access) {
                    $keyfilePubAcl.RemoveAccessRule($accessRule)
                }
                # Add a new access rule for the current user with Read and Write permissions
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Add a new access rule for the 'Users' group with Read permissions
                $sid = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, "Read", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                if ((Test-IsAdminWindows) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path "$using:keyfile.pub" -AclObject $using:keyfilePubAcl
                    }
                } else {
                    Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl
                }

                # Remove sshPass environment variable
                Remove-Variable -Name sshPass -ErrorAction SilentlyContinue -Scope Global
            }
        }
    } elseif (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and
        (
            $PSVersionTable.Platform -eq 'Unix' -or
            [System.Environment]::OSVersion.Platform -eq 'Unix'
        )
    ) {
        # We are on Linux
        $sshPath = "/usr/bin/ssh"
        $ncatPath = "/usr/bin/ncat"

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes openssh-client
            }
        }

        # Install ncat if not already installed
        if (-not (Test-Path $ncatPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes ncat
            }
        }

        # Generate a random password for SSH
        $sshPass = -join ((65..90) + (97..122) + (48..57) | Get-SecureRandom -Count 32 | ForEach-Object { [char]$_ })

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:HOME -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            # On Linux, check if the filesystem is Btrfs
            $btrfsCommand = Get-Command btrfs -ErrorAction SilentlyContinue
            if ((Invoke-Command { df --type=btrfs / }) -and $btrfsCommand) {
                # If it is Btrfs, create a Btrfs subvolume
                Invoke-Command { btrfs subvolume create $sshDirPath }
            } else {
                # If it is not Btrfs or btrfs command doesn't exist, just create the directory
                New-Item -ItemType Directory -Force -Path $sshDirPath
            }
        }

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwPath = Join-Path -Path $sshDirPath -ChildPath ".pw"
        if (-not (Test-Path $pwPath)) {
            New-Item -ItemType Directory -Force -Path $pwPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        # On Linux, use chmod command to set permissions
        Invoke-Command { chmod -R 700 $sshDirPath }

        # Get the hostname of the machine
        $hostname = (Invoke-Command { hostname }).Trim()
        $hash = -join ((0..9) + ('a'..'z') | Get-SecureRandom -Count 6)
        $keyName = "$RemoteHost.$RemoteUser" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if sshPass and keyName are not null
            if ($null -ne $sshPass -and $null -ne $keyName) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$keyName"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write sshPass to pw file
                Set-Content -Path $pwFilePath -Value $sshPass
                # Set $pwFilePath permission to 400
                Invoke-Command { chmod 400 $pwFilePath }

                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$Id$keyName.key"
                ssh-keygen $keyOptions -f $keyfile -N $sshPass
                # Set $keyfile permissions
                Invoke-Command { chmod 600 $keyfile }

                # Set "$keyfile.pub" permissions
                Invoke-Command { chmod 644 "$keyfile.pub" }

                # Remove sshPass environment variable
                Remove-Variable -Name sshPass -ErrorAction SilentlyContinue -Scope Global
            }
        }
    }

    # $config = Join-Path -Path $sshDirPath -ChildPath "config"
    $config = Join-Path -Path $sshDirPath.FullName -ChildPath "config"

    if (Test-Path -Path $keyfile) {
        $configContent = @"
Host                 $RemoteHost.$RemoteUser
Hostname             $RemoteHost
IdentitiesOnly       yes
IdentityFile         $keyfile
User                 git
ProxyCommand         ncat --proxy 127.0.0.1:9050 --proxy-type socks5 %h %p

"@

        Add-Content -Path $config -Value $configContent
    }
}
Export-ModuleMember -Function "Set-SSHKeyPasswordProtected"

function Set-SSHKeyPasswordless {
    <#
.SYNOPSIS
    Sets up passwordless SSH key authentication for a remote host.

.DESCRIPTION
    The Set-SSHKeyPasswordless function generates SSH key pairs and configures the necessary settings for passwordless SSH key authentication on both Windows and Linux systems. It installs required dependencies, creates the .ssh directory, sets appropriate permissions, and adds the generated key to the SSH configuration file.

.PARAMETER RemoteHost
    The hostname or IP address of the remote host. Default is "github.com".

.PARAMETER RemoteUser
    The username for the remote host. Default is "githubuser".

.PARAMETER Keytype
    The type of SSH key to generate. Valid options are "rsa", "ecdsa", and "ed25519". Default is "ed25519".

.PARAMETER Comment
    The comment to include in the SSH key. If not specified, it will be set to "RemoteUser@RemoteHost".

.EXAMPLE
    Set-SSHKeyPasswordless -RemoteHost "example.com" -RemoteUser "user" -Keytype "rsa" -Comment "My SSH Key"
    Generates an RSA SSH key pair with the specified comment for the user "user" on the host "example.com".

.NOTES
    This function requires administrative privileges on Windows systems to install dependencies and set permissions.

    On Linux systems, this function requires sudo privileges to install dependencies and set permissions.

    The generated SSH key pair will be stored in the .ssh directory under the user's home directory.

    The SSH configuration file will be updated to include the generated key for the specified remote host.

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$RemoteHost = "github.com",
        [string]$RemoteUser = "githubuser",
        [string]$Keytype = "ed25519",
        [string]$Comment
    )

    if (-not $Comment) {
        $Comment = "$RemoteUser@$RemoteHost"
    }

    $rsaKeylength = 4096
    $ecdsaKeylength = 521

    $Kdf = Get-Random -Minimum 16 -Maximum 27

    if ($Keytype -eq "rsa") {
        $Id = "id_rsa_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-b$rsaKeylength", "-C$Comment")
    } elseif ($Keytype -eq "ecdsa") {
        $Id = "id_ecdsa_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-b$ecdsaKeylength", "-C$Comment")
    } elseif ($Keytype -eq "ed25519") {
        $Id = "id_ed25519_"
        $keyOptions = @("-a$Kdf", "-t$Keytype", "-C$Comment")
    }

    if (
        $PSVersionTable.Platform -eq 'Win32NT' -or
        [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or
        $null -eq $PSVersionTable.Platform
    ) {
        # We are on Windows
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Define the path to the winget executable
        $wingetPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
        # Check if winget is installed
        if (-not (Test-Path $wingetPath)) {
            # Winget is not installed, exit the script
            Write-Error "Winget is not installed."
            Break
        }

        # Install gsudo if not already installed
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Install-WindowsGsudo -gsudoPath $gsudoPath

        # Install openssh client if not already installed
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        Install-WindowsOpenSSHClient -SshPath $sshPath

        # Install Nmap if not already installed
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        Install-WindowsNmap -ncatPath $ncatPath

        # Create .ssh directory if not already exists
        $sshDirPath = New-DirectoryIfNotExist -Path $([Environment]::GetFolderPath("USERPROFILE")) -ChildPath ".ssh"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permission -Item $sshDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

        # Password for SSH
        $sshPass = ""

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $chars = @(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z'
        )
        $hash = -join (1..6 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $keyName = "$RemoteHost.$RemoteUser" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath.FullName)) {
            # Check if sshPass and keyName are not null
            if ($sshPass -eq "" -and $null -ne $keyName) {
                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath.FullName -ChildPath "$Id$keyName.key"
                ssh-keygen $keyOptions -f $keyfile -N $sshPass
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                if ((Test-IsAdminWindows) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path $using:keyfile -AclObject $using:keyfileAcl
                        # Set-Permission -Item $using:keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
                    # Set-Permission -Item $keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                }

                # Set "$keyfile.pub" permissions to 644
                # Get the existing ACL
                $keyfilePubAcl = Get-Acl -Path "$keyfile.pub"
                # Remove all existing access rules
                foreach ($accessRule in $keyfilePubAcl.Access) {
                    $keyfilePubAcl.RemoveAccessRule($accessRule)
                }
                # Add a new access rule for the current user with Read and Write permissions
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Add a new access rule for the 'Users' group with Read permissions
                $sid = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, "Read", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                if ((Test-IsAdminWindows) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path "$using:keyfile.pub" -AclObject $using:keyfilePubAcl
                    }
                } else {
                    Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl
                }

                # Remove sshPass environment variable
                Remove-Variable -Name sshPass -ErrorAction SilentlyContinue -Scope Global
            }
        }
    } elseif (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and
        (
            $PSVersionTable.Platform -eq 'Unix' -or
            [System.Environment]::OSVersion.Platform -eq 'Unix'
        )
    ) {
        # We are on Linux
        $sshPath = "/usr/bin/ssh"
        $ncatPath = "/usr/bin/ncat"

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes openssh-client
            }
        }

        # Install ncat if not already installed
        if (-not (Test-Path $ncatPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes ncat
            }
        }

        # Generate a random password for SSH
        $sshPass = -join ((65..90) + (97..122) + (48..57) | Get-SecureRandom -Count 32 | ForEach-Object { [char]$_ })

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:HOME -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            # On Linux, check if the filesystem is Btrfs
            $btrfsCommand = Get-Command btrfs -ErrorAction SilentlyContinue
            if ((Invoke-Command { df --type=btrfs / }) -and $btrfsCommand) {
                # If it is Btrfs, create a Btrfs subvolume
                Invoke-Command { btrfs subvolume create $sshDirPath }
            } else {
                # If it is not Btrfs or btrfs command doesn't exist, just create the directory
                New-Item -ItemType Directory -Force -Path $sshDirPath
            }
        }

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwPath = Join-Path -Path $sshDirPath -ChildPath ".pw"
        if (-not (Test-Path $pwPath)) {
            New-Item -ItemType Directory -Force -Path $pwPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        # On Linux, use chmod command to set permissions
        Invoke-Command { chmod -R 700 $sshDirPath }

        # Get the hostname of the machine
        $hostname = (Invoke-Command { hostname }).Trim()
        $hash = -join ((0..9) + ('a'..'z') | Get-SecureRandom -Count 6)
        $keyName = "$RemoteHost.$RemoteUser" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if sshPass and keyName are not null
            if ($null -ne $sshPass -and $null -ne $keyName) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$keyName"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write sshPass to pw file
                Set-Content -Path $pwFilePath -Value $sshPass
                # Set $pwFilePath permission to 400
                Invoke-Command { chmod 400 $pwFilePath }

                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$Id$keyName.key"
                ssh-keygen $keyOptions -f $keyfile -N $sshPass
                # Set $keyfile permissions
                Invoke-Command { chmod 600 $keyfile }

                # Set "$keyfile.pub" permissions
                Invoke-Command { chmod 644 "$keyfile.pub" }

                # Remove sshPass environment variable
                Remove-Variable -Name sshPass -ErrorAction SilentlyContinue -Scope Global
            }
        }
    }

    # $config = Join-Path -Path $sshDirPath -ChildPath "config"
    $config = Join-Path -Path $sshDirPath.FullName -ChildPath "config"

    if (Test-Path -Path $keyfile) {
        $configContent = @"
Host                 $RemoteHost.$RemoteUser
Hostname             $RemoteHost
IdentitiesOnly       yes
IdentityFile         $keyfile
User                 git
ProxyCommand         ncat --proxy 127.0.0.1:9050 --proxy-type socks5 %h %p

"@

        Add-Content -Path $config -Value $configContent
    }
}
Export-ModuleMember -Function "Set-SSHKeyPasswordless"
