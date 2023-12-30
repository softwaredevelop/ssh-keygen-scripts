# Set execution policy to RemoteSigned
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Function to generate SSH keys and configure SSH client
function keygen_without_p {

    $RSA_KEYLENGTH = 4096
    $ECDSA_KEYLENGTH = 521

    $KDF = Get-Random -Minimum 16 -Maximum 27

    $REMOTE_HOSTNAME = if ($args[0]) { $args[0] } else { "gh" }
    $REMOTE_USER = if ($args[1]) { $args[1] } else { "ghuser" }
    $KEYTYPE = if ($args[2]) { $args[2] } else { "ed25519" }
    $SSHPASS = ""
    $COMMENT = if ($args[3]) { $args[3] } else { "$REMOTE_USER@$REMOTE_HOSTNAME" }

    if ($KEYTYPE -eq "rsa") {
        $ID = "id_rsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$RSA_KEYLENGTH", "-C$COMMENT")
    } elseif ($KEYTYPE -eq "ecdsa") {
        $ID = "id_ecdsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$ECDSA_KEYLENGTH", "-C$COMMENT")
    } elseif ($KEYTYPE -eq "ed25519") {
        $ID = "id_ed25519_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-C$COMMENT")
    }

    if (($PSVersionTable.PSEdition -eq 'Desktop') -and
        (
            [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or
            $PSVersionTable.Platform -eq 'Win32NT' -or
            $null -eq $PSVersionTable.Platform
        )
    ) {
        # We are on Windows
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        }

        # Define the path to the winget executable
        $wingetPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
        # Check if winget is installed
        if (-not (Test-Path $wingetPath)) {
            # Winget is not installed, install it
            Add-AppxPackage -Path "https://aka.ms/installwinget"
        }

        # Install Nmap if not already installed
        if (-not (Test-Path $ncatPath)) {
            winget install --id=Insecure.Nmap
        }

        # Install gsudo if not already installed
        if (-not (Test-Path $gsudoPath)) {
            winget install --id=gerardog.gsudo
        }

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            New-Item -ItemType Directory -Force -Path $sshDirPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        $sshDirPathAcl = Get-Acl -Path $sshDirPath
        foreach ($accessRule in $sshDirPathAcl.Access) {
            $sshDirPathAcl.RemoveAccessRule($accessRule)
        }
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "FullControl", "Allow")
        $sshDirPathAcl.AddAccessRule($accessRule)
        Set-Acl -Path $sshDirPath -AclObject $sshDirPathAcl

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $chars = @(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z'
        )
        $hash = -join (1..6 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            function Test-Admin {
                $currentUser = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
                $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
            }
            # Check if SSHPASS and KEYNAME are not null
            if ($SSHPASS -eq "" -and $null -ne $KEYNAME) {
                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                if ((Test-Admin) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path $using:keyfile -AclObject $using:keyfileAcl
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
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
                if ((Test-Admin) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path "$using:keyfile.pub" -AclObject $using:keyfilePubAcl
                    }
                } else {
                    Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl
                }

                # Remove SSHPASS environment variable
                Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
            }
        }
    } elseif (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and
        (
            [System.Environment]::OSVersion.Platform -eq 'Unix' -or
            $PSVersionTable.Platform -eq 'Unix'
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

        # Set permissions to 700 (Owner can read, write and execute)
        # On Linux, use chmod command to set permissions
        Invoke-Command { chmod -R 700 $sshDirPath }

        # Get the hostname of the machine
        $hostname = (Invoke-Command { hostname }).Trim()
        $hash = -join ((0..9) + ('a'..'z') | Get-SecureRandom -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($SSHPASS -eq "" -and $null -ne $KEYNAME) {
                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions
                Invoke-Command { chmod 600 $keyfile }

                # Set "$keyfile.pub" permissions
                Invoke-Command { chmod 644 "$keyfile.pub" }

                # Remove SSHPASS environment variable
                Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
            }
        }
    }

    $config = Join-Path -Path $sshDirPath -ChildPath "config"

    if (Test-Path -Path $keyfile) {
        $configContent = @"
Host                 $REMOTE_HOSTNAME.$REMOTE_USER
Hostname             $REMOTE_HOSTNAME
IdentitiesOnly       yes
IdentityFile         $keyfile
User                 git
ProxyCommand         ncat --proxy 127.0.0.1:9050 --proxy-type socks5 %h %p

"@

        Add-Content -Path $config -Value $configContent
    }
}

# Check if profile file exists, if not, create it
if (!(Test-Path -Path $PROFILE)) {
    New-Item -Type File -Path $PROFILE -Force
}

# Function to generate SSH keys and configure SSH client
$keygenFunction = @'
function keygen_without_p {

    $RSA_KEYLENGTH = 4096
    $ECDSA_KEYLENGTH = 521

    $KDF = Get-Random -Minimum 16 -Maximum 27

    $REMOTE_HOSTNAME = if ($args[0]) { $args[0] } else { "gh" }
    $REMOTE_USER = if ($args[1]) { $args[1] } else { "ghuser" }
    $KEYTYPE = if ($args[2]) { $args[2] } else { "ed25519" }
    $SSHPASS = ""
    $COMMENT = if ($args[3]) { $args[3] } else { "$REMOTE_USER@$REMOTE_HOSTNAME" }

    if ($KEYTYPE -eq "rsa") {
        $ID = "id_rsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$RSA_KEYLENGTH", "-C$COMMENT")
    } elseif ($KEYTYPE -eq "ecdsa") {
        $ID = "id_ecdsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$ECDSA_KEYLENGTH", "-C$COMMENT")
    } elseif ($KEYTYPE -eq "ed25519") {
        $ID = "id_ed25519_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-C$COMMENT")
    }

    if (($PSVersionTable.PSEdition -eq 'Desktop') -and
        (
            [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or
            $PSVersionTable.Platform -eq 'Win32NT' -or
            $null -eq $PSVersionTable.Platform
        )
    ) {
        # We are on Windows
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        $ncatPath = "C:\Program Files (x86)\Nmap\ncat.exe"
        $gsudoPath = "C:\Program Files\gsudo\Current\gsudo.exe"
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        }

        # Define the path to the winget executable
        $wingetPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
        # Check if winget is installed
        if (-not (Test-Path $wingetPath)) {
            # Winget is not installed, install it
            Add-AppxPackage -Path "https://aka.ms/installwinget"
        }

        # Install Nmap if not already installed
        if (-not (Test-Path $ncatPath)) {
            winget install --id=Insecure.Nmap
        }

        # Install gsudo if not already installed
        if (-not (Test-Path $gsudoPath)) {
            winget install --id=gerardog.gsudo
        }

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            New-Item -ItemType Directory -Force -Path $sshDirPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        $sshDirPathAcl = Get-Acl -Path $sshDirPath
        foreach ($accessRule in $sshDirPathAcl.Access) {
            $sshDirPathAcl.RemoveAccessRule($accessRule)
        }
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "FullControl", "Allow")
        $sshDirPathAcl.AddAccessRule($accessRule)
        Set-Acl -Path $sshDirPath -AclObject $sshDirPathAcl

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $chars = @(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z'
        )
        $hash = -join (1..6 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            function Test-Admin {
                $currentUser = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
                $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
            }
            # Check if SSHPASS and KEYNAME are not null
            if ($SSHPASS -eq "" -and $null -ne $KEYNAME) {
                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                if ((Test-Admin) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path $using:keyfile -AclObject $using:keyfileAcl
                    }
                } else {
                    Set-Acl -Path $keyfile -AclObject $keyfileAcl
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
                if ((Test-Admin) -eq $false) {
                    Invoke-Gsudo {
                        Set-Acl -Path "$using:keyfile.pub" -AclObject $using:keyfilePubAcl
                    }
                } else {
                    Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl
                }

                # Remove SSHPASS environment variable
                Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
            }
        }
    } elseif (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and
        (
            [System.Environment]::OSVersion.Platform -eq 'Unix' -or
            $PSVersionTable.Platform -eq 'Unix'
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

        # Set permissions to 700 (Owner can read, write and execute)
        # On Linux, use chmod command to set permissions
        Invoke-Command { chmod -R 700 $sshDirPath }

        # Get the hostname of the machine
        $hostname = (Invoke-Command { hostname }).Trim()
        $hash = -join ((0..9) + ('a'..'z') | Get-SecureRandom -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($SSHPASS -eq "" -and $null -ne $KEYNAME) {
                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions
                Invoke-Command { chmod 600 $keyfile }

                # Set "$keyfile.pub" permissions
                Invoke-Command { chmod 644 "$keyfile.pub" }

                # Remove SSHPASS environment variable
                Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
            }
        }
    }

    $config = Join-Path -Path $sshDirPath -ChildPath "config"

    if (Test-Path -Path $keyfile) {
        $configContent = @"
Host                 $REMOTE_HOSTNAME.$REMOTE_USER
Hostname             $REMOTE_HOSTNAME
IdentitiesOnly       yes
IdentityFile         $keyfile
User                 git
ProxyCommand         ncat --proxy 127.0.0.1:9050 --proxy-type socks5 %h %p

"@

        Add-Content -Path $config -Value $configContent
    }
}
'@

# Add the keygen function to the profile file
Add-Content -Path $PROFILE -Value $keygenFunction
