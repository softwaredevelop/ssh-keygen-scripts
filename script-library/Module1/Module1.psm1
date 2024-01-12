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

function Test-IsAdminWindows {
    <#
.SYNOPSIS
Checks if the current user is an administrator.

.DESCRIPTION
The Test-IsAdmin function checks if the current user has administrative privileges.

.PARAMETER None
This function does not accept any parameters.

.EXAMPLE
Test-IsAdminWindows
Checks if the current user is an administrator.

.OUTPUTS
[System.Boolean]
Returns $true if the current user is an administrator, otherwise returns $false.
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

    if (-not (Test-IsAdminWindows)) {
        Write-Host "Error: This script must be run with administrator privileges1." -ForegroundColor Red
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
    Checks for updates and installs them if available.

.DESCRIPTION
    The Update-System function checks for Windows updates using the Get-WindowsUpdate cmdlet. If updates are available, it installs them using the Install-WindowsUpdate cmdlet. The script must be run with administrator privileges.

.PARAMETER Update
    Specifies the type of update to check and install. Valid values are "WindowsUpdate" and "MicrosoftUpdate".

.EXAMPLE
    Update-System -Update "WindowsUpdate"
    Checks for Windows updates and installs them if available.

.EXAMPLE
    Update-System -Update "MicrosoftUpdate"
    Checks for Microsoft updates and installs them if available.
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [string]$Update = "WindowsUpdate"
    )

    if (-not (Test-IsAdminWindows)) {
        Write-Error -Message "Error: This script must be run with administrator privileges." -ErrorId "NotAdmin"
        Break
    }

    $updates = Invoke-Expression ("Get-WindowsUpdate -" + $Update)

    if ($updates.Count -gt 0) {
        Invoke-Expression ("Install-WindowsUpdate -" + $Update + " -AcceptAll -IgnoreReboot")
    } else {
        Write-Host "No updates available for ${Update}."
    }
}
Export-ModuleMember -Function "Update-System"

function Install-GsudoWindows {
    <#
.SYNOPSIS
Installs Gsudo for Windows.

.DESCRIPTION
This function installs Gsudo for Windows if it is not already installed.

.PARAMETER gsudoPath
The path to the Gsudo executable.

.EXAMPLE
Install-GsudoWindows -gsudoPath "C:\Program Files\Gsudo\gsudo.exe"
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

function Install-OpenSSHClientWindows {
    <#
.SYNOPSIS
Installs the OpenSSH client on Windows.

.DESCRIPTION
The Install-OpenSSHClientWindows function installs the OpenSSH client on Windows if it is not already installed. It requires the path to the SSH executable as a parameter.

.PARAMETER SshPath
The path to the SSH executable.

.EXAMPLE
Install-OpenSSHClientWindows -SshPath "C:\OpenSSH\ssh.exe"
Installs the OpenSSH client using the specified path to the SSH executable.

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SshPath
    )
    if (-not (Test-Path $SshPath)) {
        if ((Test-IsAdminWindows) -eq $false) {
            Invoke-Gsudo {
                Add-WindowsCapability -Online -Name OpenSSH.Client~~~~
            }
        } else {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~
        }
    }
}

function Install-NmapWindows {
    <#
.SYNOPSIS
Installs Nmap on Windows if it is not already installed.

.DESCRIPTION
The Install-NmapWindows function installs Nmap on Windows if it is not already installed. It checks if the specified ncatPath exists, and if not, it uses the winget command to install the Insecure.Nmap package.

.PARAMETER ncatPath
The path to the ncat executable.

.EXAMPLE
Install-NmapWindows -ncatPath "C:\Program Files\Nmap\ncat.exe"
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

function New-DirectoryIfNotExists {
    <#
.SYNOPSIS
Creates a new directory if it does not already exist.

.DESCRIPTION
The New-DirectoryIfNotExists function creates a new directory at the specified path if it does not already exist.

.PARAMETER Path
The parent path where the new directory will be created.

.PARAMETER ChildPath
The name of the new directory.

.EXAMPLE
New-DirectoryIfNotExists -Path "C:\Temp" -ChildPath "NewFolder"

This example creates a new directory named "NewFolder" under the "C:\Temp" directory if it does not already exist.

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

function Set-Permissions {
    <#
.SYNOPSIS
Sets permissions for a specified item.

.DESCRIPTION
The Set-Permissions function is used to set permissions for a specified item in the file system. It removes any existing access rules for the item and adds a new access rule based on the provided parameters.

.PARAMETER Item
The path of the item for which permissions need to be set.

.PARAMETER IdentityReference
The identity reference for the user or group to which the permissions will be applied.

.PARAMETER FileSystemRights
The file system rights to be granted to the user or group.

.PARAMETER AccessControlType
The type of access control to be applied, such as Allow or Deny.

.EXAMPLE
Set-Permissions -Item "C:\Path\To\File.txt" -IdentityReference "DOMAIN\Username" -FileSystemRights "Read" -AccessControlType "Allow"
Sets the permissions for the specified file, granting read access to the user "DOMAIN\Username".

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

function Set-SSHKeysPasswordProtected {
    <#
.SYNOPSIS
Generates password-protected SSH keys for a remote host.

.DESCRIPTION
The Set-SSHKeysPasswordProtected function generates password-protected SSH keys for a specified remote host. It supports different key types such as RSA, ECDSA, and Ed25519. The function installs necessary dependencies, creates the required directories, and sets appropriate permissions. It generates a random password for the SSH keys and saves it securely. The generated keys are stored in the .ssh directory.

.PARAMETER RemoteHost
The hostname or IP address of the remote host. Default is "github.com".

.PARAMETER RemoteUser
The username for the remote host. Default is "githubuser".

.PARAMETER Keytype
The type of SSH key to generate. Valid values are "rsa", "ecdsa", and "ed25519". Default is "ed25519".

.PARAMETER Comment
The comment to include in the SSH key. If not specified, it will be set to "RemoteUser@RemoteHost".

.EXAMPLE
Set-SSHKeysPasswordProtected -RemoteHost "example.com" -RemoteUser "user" -Keytype "rsa" -Comment "My RSA Key"
Generates RSA SSH keys with the specified remote host, remote user, and comment.

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
            Write-Host "Winget is not installed." -ForegroundColor Red
            Break
        }

        # Install gsudo if not already installed
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Install-GsudoWindows -gsudoPath $gsudoPath

        # Install openssh client if not already installed
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        Install-OpenSSHClientWindows -SshPath $sshPath

        # Install Nmap if not already installed
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        Install-NmapWindows -ncatPath $ncatPath

        # Create .ssh directory if not already exists
        $sshDirPath = New-DirectoryIfNotExists -Path $([Environment]::GetFolderPath("USERPROFILE")) -ChildPath ".ssh"

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwDirPath = New-DirectoryIfNotExists -Path $sshDirPath.FullName -ChildPath ".pw"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permissions -Item $sshDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permissions -Item $pwDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

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
                Set-Permissions -Item $pwFilePath -IdentityReference $env:USERNAME -FileSystemRights "Read" -AccessControlType "Allow"

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
                        # Set-Permissions -Item $using:keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
                    # Set-Permissions -Item $keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
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
Export-ModuleMember -Function "Set-SSHKeysPasswordProtected"

function Set-SSHKeysPasswordless {
    <#
.SYNOPSIS
Sets up passwordless SSH keys for a remote host.

.DESCRIPTION
The Set-SSHKeysPasswordless function generates SSH key pairs and sets up passwordless authentication for a remote host. It installs necessary dependencies, creates the .ssh directory, generates the SSH keys, and sets appropriate permissions.

.PARAMETER RemoteHost
The hostname or IP address of the remote host. Default is "github.com".

.PARAMETER RemoteUser
The username for the remote host. Default is "githubuser".

.PARAMETER Keytype
The type of SSH key to generate. Valid options are "ed25519", "rsa", and "ecdsa". Default is "ed25519".

.PARAMETER Comment
The comment to include in the SSH key. If not specified, it will be set to "RemoteUser@RemoteHost".

.EXAMPLE
Set-SSHKeysPasswordless -RemoteHost "example.com" -RemoteUser "user" -Keytype "rsa" -Comment "My SSH Key"
Generates RSA SSH key pair for the remote host "example.com" with the username "user" and the comment "My SSH Key".

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
            Write-Host "Winget is not installed." -ForegroundColor Red
            Break
        }

        # Install gsudo if not already installed
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Install-GsudoWindows -gsudoPath $gsudoPath

        # Install openssh client if not already installed
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        Install-OpenSSHClientWindows -SshPath $sshPath

        # Install Nmap if not already installed
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        Install-NmapWindows -ncatPath $ncatPath

        # Create .ssh directory if not already exists
        $sshDirPath = New-DirectoryIfNotExists -Path $([Environment]::GetFolderPath("USERPROFILE")) -ChildPath ".ssh"

        # Set permissions to 700 (Owner can read, write and execute)
        Set-Permissions -Item $sshDirPath.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"

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
                        # Set-Permissions -Item $using:keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
                    # Set-Permissions -Item $keyfile -IdentityReference $env:USERNAME -FileSystemRights "Read, Write" -AccessControlType "Allow"
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
Export-ModuleMember -Function "Set-SSHKeysPasswordless"
