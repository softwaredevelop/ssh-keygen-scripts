# Set execution policy to RemoteSigned
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Function to generate SSH keys and configure SSH client
function keygen {
    # We are on Linux
    $sshPath = "/usr/bin/ssh"
    $ncPath = "/usr/bin/nc"
    $installCommand = 'sudo apt-get update && sudo apt-get install --no-install-recommends --assume-yes'

    # Install openssh client if not already installed
    if (-not (Test-Path $sshPath)) {
        Invoke-Expression "$installCommand openssh-client"
    }

    # Install netcat if not already installed
    if (-not (Test-Path $ncPath)) {
        Invoke-Expression "$installCommand netcat-openbsd"
    }

    # Generate a random password for SSH
    $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

    # Get the hostname of the machine
    $hostname = (Invoke-Expression "hostname").Trim()

    $sshPath = Join-Path -Path $env:HOME -ChildPath ".ssh"
    # Create .ssh directory if not already exists
    if (-not (Test-Path $sshPath)) {
        # On Linux, check if the filesystem is Btrfs
        $btrfsCommand = Get-Command btrfs -ErrorAction SilentlyContinue
        if ((Invoke-Expression "df --type=btrfs /") -and $btrfsCommand) {
            # If it is Btrfs, create a Btrfs subvolume
            Invoke-Expression "btrfs subvolume create $sshPath"
        }
        else {
            # If it is not Btrfs or btrfs command doesn't exist, just create the directory
            New-Item -ItemType Directory -Force -Path $sshPath
        }
    }

    # Check if .pw directory exists inside .ssh directory, if not, create it
    $pwPath = Join-Path -Path $sshPath -ChildPath ".pw"
    if (-not (Test-Path $pwPath)) {
        New-Item -ItemType Directory -Force -Path $pwPath
    }

    # Set permissions to 700 (Owner can read, write and execute)
    # On Linux, use chmod command to set permissions
    Invoke-Expression "chmod -R 700 $sshPath"

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
    }
    elseif ($KEYTYPE -eq "ecdsa") {
        $ID = "id_ecdsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$ECDSA_KEYLENGTH", "-C$COMMENT")
    }
    elseif ($KEYTYPE -eq "ed25519") {
        $ID = "id_ed25519_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-C$COMMENT")
    }

    $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
    $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

    # Check if ssh-keygen exists and .ssh directory exists
    if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshPath)) {
        # Check if SSHPASS and KEYNAME are not null
        if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
            $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
            # Create .pw directory if it doesn't exist
            if (!(Test-Path -Path $pwPath)) {
                New-Item -ItemType Directory -Force -Path $pwPath
            }
            # Write SSHPASS to pw file
            Set-Content -Path $pwFilePath -Value $SSHPASS
            # Set file permission to 400
            Invoke-Expression "chmod 400 $pwFilePath"
            # Run ssh-keygen
            $keyfile = Join-Path -Path $sshPath -ChildPath "$ID$KEYNAME.key"
            ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
            # Set file permissions
            Invoke-Expression "chmod 600 $keyfile"
            # Set file permissions
            Invoke-Expression "chmod 644 $keyfile.pub"
            # Remove SSHPASS environment variable
            Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
        }
    }

    $config = Join-Path -Path $sshPath -ChildPath "config"

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
    # We are on Linux
    $sshPath = "/usr/bin/ssh"
    $ncPath = "/usr/bin/nc"
    $installCommand = 'sudo apt-get update && sudo apt-get install --no-install-recommends --assume-yes'

    # Install openssh client if not already installed
    if (-not (Test-Path $sshPath)) {
        Invoke-Expression "$installCommand openssh-client"
    }

    # Install netcat if not already installed
    if (-not (Test-Path $ncPath)) {
        Invoke-Expression "$installCommand netcat-openbsd"
    }

    # Generate a random password for SSH
    $SSHPASS = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

    # Get the hostname of the machine
    $hostname = (Invoke-Expression "hostname").Trim()

    $sshPath = Join-Path -Path $env:HOME -ChildPath ".ssh"
    # Create .ssh directory if not already exists
    if (-not (Test-Path $sshPath)) {
        # On Linux, check if the filesystem is Btrfs
        $btrfsCommand = Get-Command btrfs -ErrorAction SilentlyContinue
        if ((Invoke-Expression "df --type=btrfs /") -and $btrfsCommand) {
            # If it is Btrfs, create a Btrfs subvolume
            Invoke-Expression "btrfs subvolume create $sshPath"
        }
        else {
            # If it is not Btrfs or btrfs command doesn't exist, just create the directory
            New-Item -ItemType Directory -Force -Path $sshPath
        }
    }

    # Check if .pw directory exists inside .ssh directory, if not, create it
    $pwPath = Join-Path -Path $sshPath -ChildPath ".pw"
    if (-not (Test-Path $pwPath)) {
        New-Item -ItemType Directory -Force -Path $pwPath
    }

    # Set permissions to 700 (Owner can read, write and execute)
    # On Linux, use chmod command to set permissions
    Invoke-Expression "chmod -R 700 $sshPath"

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
    }
    elseif ($KEYTYPE -eq "ecdsa") {
        $ID = "id_ecdsa_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-b$ECDSA_KEYLENGTH", "-C$COMMENT")
    }
    elseif ($KEYTYPE -eq "ed25519") {
        $ID = "id_ed25519_"
        $KEYOPT = @("-a$KDF", "-t$KEYTYPE", "-C$COMMENT")
    }

    $hash = -join ((0..9) + ('a'..'f') | Get-Random -Count 6)
    $KEYNAME = "$REMOTE_HOSTNAME.$REMOTE_USER" + "_" + $hostname + "_" + $hash

    # Check if ssh-keygen exists and .ssh directory exists
    if ((Get-Command ssh-keygen -ErrorAction SilentlyContinue) -and (Test-Path -Path $sshPath)) {
        # Check if SSHPASS and KEYNAME are not null
        if ($null -ne $SSHPASS -and $null -ne $KEYNAME) {
            $pwFilePath = Join-Path -Path $pwPath -ChildPath "pw_$KEYNAME"
            # Create .pw directory if it doesn't exist
            if (!(Test-Path -Path $pwPath)) {
                New-Item -ItemType Directory -Force -Path $pwPath
            }
            # Write SSHPASS to pw file
            Set-Content -Path $pwFilePath -Value $SSHPASS
            # Set file permission to 400
            Invoke-Expression "chmod 400 $pwFilePath"
            # Run ssh-keygen
            $keyfile = Join-Path -Path $sshPath -ChildPath "$ID$KEYNAME.key"
            ssh-keygen $KEYOPT -f $keyfile -N $SSHPASS
            # Set file permissions
            Invoke-Expression "chmod 600 $keyfile"
            # Set file permissions
            Invoke-Expression "chmod 644 $keyfile.pub"
            # Remove SSHPASS environment variable
            Remove-Variable -Name SSHPASS -ErrorAction SilentlyContinue -Scope Global
        }
    }

    $config = Join-Path -Path $sshPath -ChildPath "config"

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
