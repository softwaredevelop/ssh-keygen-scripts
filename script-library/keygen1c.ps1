# Set execution policy to RemoteSigned
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Function to generate SSH keys and configure SSH client
function keygen {

    $RSA_KEYLENGTH = 4096
    $ECDSA_KEYLENGTH = 521

    $KDF = Get-Random -Minimum 16 -Maximum 27

    $REMOTE_HOSTNAME = if ($args[0]) { $args[0] } else { "gh" }
    $REMOTE_USER = if ($args[1]) { $args[1] } else { "ghuser" }
    $KEYTYPE = if ($args[2]) { $args[2] } else { "ed25519" }
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

    if (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and
        (
            [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or
            $PSVersionTable.Platform -eq 'Win32NT' -or
            $null -eq $PSVersionTable.Platform
        )
    ) {
        # if (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and $PSVersionTable.Platform -eq 'Win32NT') {
        # We are on Windows
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        # $ncPath = "$env:SYSTEMROOT\System32\OpenSSH\nc.exe"
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        }

        # # Install netcat if not already installed
        # if (-not (Test-Path $ncPath)) {
        #     Invoke-Command -ScriptBlock {
        #         sudo apt-get update
        #         sudo apt-get install --no-install-recommends --assume-yes netcat-openbsd
        #     }
        # }

        # Generate a random password for SSH
        $SSHPASS = [System.Web.Security.Membership]::GeneratePassword(32, 4)
        # $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        # $SSHPASS = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            New-Item -ItemType Directory -Force -Path $sshDirPath
        }

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwPath = Join-Path -Path $sshDirPath -ChildPath ".pw"
        if (-not (Test-Path $pwPath)) {
            New-Item -ItemType Directory -Force -Path $pwPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        # On Windows, use icacls command to set permissions
        # Invoke-Command -ScriptBlock { icacls $sshDirPath /grant:r "$($env:USERNAME):(OI)(CI)F" /T }
        $sshDirPathAcl = Get-Acl -Path $sshDirPath
        foreach ($accessRule in $sshDirPathAcl.Access) {
            $sshDirPathAcl.RemoveAccessRule($accessRule)
        }
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
        $sshDirPathAcl.AddAccessRule($accessRule)
        Set-Acl -Path $sshDirPath -AclObject $sshDirPathAcl

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write SSHPASS to pw file
                Set-Content -Path $pwFilePath -Value $SSHPASS
                # Set $pwFilePath permission to 400
                $pwFilePathAcl = Get-Acl -Path $pwFilePath
                foreach ($accessRule in $pwFilePathAcl.Access) {
                    $pwFilePathAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read", "Allow")
                $pwFilePathAcl.SetAccessRule($accessRule)
                Set-Acl -Path $pwFilePath -AclObject $pwFilePathAcl

                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                Set-Acl -Path $keyfile -AclObject $acl

                # Set "$keyfile.pub" permissions to 644
                # Get the existing ACL
                $keyfilePubAcl = Get-Acl -Path "$keyfile.pub"
                # Remove all existing access rules
                foreach ($accessRule in $keyfilePubAcl.Access) {
                    $acl.RemoveAccessRule($accessRule)
                }
                # Add a new access rule for the current user with Read and Write permissions
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read, Write", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Add a new access rule for the 'Users' group with Read permissions
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Read", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Set the new ACL
                Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl

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
        # } elseif ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Unix') {
        # We are on Linux
        $sshPath = "/usr/bin/ssh"
        $ncPath = "/usr/bin/nc"

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes openssh-client
            }
        }

        # Install netcat if not already installed
        if (-not (Test-Path $ncPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes netcat-openbsd
            }
        }

        # Generate a random password for SSH
        $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        # $SSHPASS = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

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
        $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write SSHPASS to pw file
                Set-Content -Path $pwFilePath -Value $SSHPASS
                # Set $pwFilePath permission to 400
                Invoke-Command { chmod 400 $pwFilePath }

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
ProxyCommand         nc -X 5 -x 127.0.0.1:9050 %h %p

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
function keygen {

    $RSA_KEYLENGTH = 4096
    $ECDSA_KEYLENGTH = 521

    $KDF = Get-Random -Minimum 16 -Maximum 27

    $REMOTE_HOSTNAME = if ($args[0]) { $args[0] } else { "gh" }
    $REMOTE_USER = if ($args[1]) { $args[1] } else { "ghuser" }
    $KEYTYPE = if ($args[2]) { $args[2] } else { "ed25519" }
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

    if (($PSVersionTable.PSEdition -eq 'Desktop' -or $PSVersionTable.PSEdition -eq 'Core') -and $PSVersionTable.Platform -eq 'Win32NT') {
        # We are on Windows
        $sshPath = "$env:SYSTEMROOT\System32\OpenSSH\ssh.exe"
        # $ncPath = "$env:SYSTEMROOT\System32\OpenSSH\nc.exe"
        Set-ExecutionPolicy RemoteSigned -Scope Process

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        }

        # # Install netcat if not already installed
        # if (-not (Test-Path $ncPath)) {
        #     Invoke-Command -ScriptBlock {
        #         sudo apt-get update
        #         sudo apt-get install --no-install-recommends --assume-yes netcat-openbsd
        #     }
        # }

        # Generate a random password for SSH
        $SSHPASS = [System.Web.Security.Membership]::GeneratePassword(32, 4)
        # $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        # $SSHPASS = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

        # Set the path to the .ssh directory
        $sshDirPath = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
        # Create .ssh directory if not already exists
        if (-not (Test-Path $sshDirPath)) {
            New-Item -ItemType Directory -Force -Path $sshDirPath
        }

        # Check if .pw directory exists inside .ssh directory, if not, create it
        $pwPath = Join-Path -Path $sshDirPath -ChildPath ".pw"
        if (-not (Test-Path $pwPath)) {
            New-Item -ItemType Directory -Force -Path $pwPath
        }

        # Set permissions to 700 (Owner can read, write and execute)
        # On Windows, use icacls command to set permissions
        # Invoke-Command -ScriptBlock { icacls $sshDirPath /grant:r "$($env:USERNAME):(OI)(CI)F" /T }
        $sshDirPathAcl = Get-Acl -Path $sshDirPath
        foreach ($accessRule in $sshDirPathAcl.Access) {
            $sshDirPathAcl.RemoveAccessRule($accessRule)
        }
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
        $sshDirPathAcl.AddAccessRule($accessRule)
        Set-Acl -Path $sshDirPath -AclObject $sshDirPathAcl

        # Get the hostname of the machine
        $hostname = $env:COMPUTERNAME
        $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write SSHPASS to pw file
                Set-Content -Path $pwFilePath -Value $SSHPASS
                # Set $pwFilePath permission to 400
                $pwFilePathAcl = Get-Acl -Path $pwFilePath
                foreach ($accessRule in $pwFilePathAcl.Access) {
                    $pwFilePathAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read", "Allow")
                $pwFilePathAcl.SetAccessRule($accessRule)
                Set-Acl -Path $pwFilePath -AclObject $pwFilePathAcl

                # Run ssh-keygen
                $keyfile = Join-Path -Path $sshDirPath -ChildPath "$ID$KEYNAME.key"
                ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
                # Set $keyfile permissions to 600
                # Get the existing ACL
                $keyfileAcl = Get-Acl -Path $keyfile
                foreach ($accessRule in $keyfileAcl.Access) {
                    $keyfileAcl.RemoveAccessRule($accessRule)
                }
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read, Write", "Allow")
                $keyfileAcl.AddAccessRule($accessRule)
                Set-Acl -Path $keyfile -AclObject $acl

                # Set "$keyfile.pub" permissions to 644
                # Get the existing ACL
                $keyfilePubAcl = Get-Acl -Path "$keyfile.pub"
                # Remove all existing access rules
                foreach ($accessRule in $keyfilePubAcl.Access) {
                    $acl.RemoveAccessRule($accessRule)
                }
                # Add a new access rule for the current user with Read and Write permissions
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "Read, Write", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Add a new access rule for the 'Users' group with Read permissions
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Read", "Allow")
                $keyfilePubAcl.AddAccessRule($accessRule)
                # Set the new ACL
                Set-Acl -Path "$keyfile.pub" -AclObject $keyfilePubAcl

                # Remove SSHPASS environment variable
                Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
            }
        }
    } elseif ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Unix') {
        # We are on Linux
        $sshPath = "/usr/bin/ssh"
        $ncPath = "/usr/bin/nc"

        # Install openssh client if not already installed
        if (-not (Test-Path $sshPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes openssh-client
            }
        }

        # Install netcat if not already installed
        if (-not (Test-Path $ncPath)) {
            Invoke-Command -ScriptBlock {
                sudo apt-get update
                sudo apt-get install --no-install-recommends --assume-yes netcat-openbsd
            }
        }

        # Generate a random password for SSH
        $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        # $SSHPASS = -join ((33..126) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

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
        $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
        $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

        # Check if ssh-keygen exists and .ssh directory exists
        if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshDirPath)) {
            # Check if SSHPASS and KEYNAME are not null
            if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
                $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
                # Create .pw directory if it doesn't exist
                if (!(Test-Path -Path $pwPath)) {
                    New-Item -ItemType Directory -Force -Path $pwPath
                }

                # Write SSHPASS to pw file
                Set-Content -Path $pwFilePath -Value $SSHPASS
                # Set $pwFilePath permission to 400
                Invoke-Command { chmod 400 $pwFilePath }

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
ProxyCommand         nc -X 5 -x 127.0.0.1:9050 %h %p

"@

        Add-Content -Path $config -Value $configContent
    }
}
'@

# Add the keygen function to the profile file
Add-Content -Path $PROFILE -Value $keygenFunction
