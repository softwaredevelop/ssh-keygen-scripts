BeforeAll {
    # Import-Module -Name (Join-Path $PWD.Path "Module1.psm1") -Force
    # Invoke-Pester -Path (Join-Path $PWD.Path "Module1.Tests.ps1") -PassThru
    # Invoke-Pester -Path (Join-Path $PWD.Path "Module1.Tests.ps1") -PassThru -OutputFile (Join-Path $PWD.Path "Module1.Tests.xml")

    # $outputFile = (Join-Path $PWD.Path "Module1.Tests.xml")
    # $pesterArgs = @{
    #     Path         = (Join-Path $PWD.Path "Module1.Tests.ps1")
    #     OutputFile   = $outputFile
    #     OutputFormat = "NUnitXml"
    #     PassThru     = $true
    # }
    # $results = Invoke-Pester @pesterArgs

    $moduleName = (Split-Path -Path $PSCommandPath -Leaf).Replace(".Tests.ps1", "")
    $loadedModule = Get-Module -Name $moduleName
    if ($loadedModule) {
        Remove-Module -Name $moduleName -Force
    }
    $modulePath = $PSCommandPath.Replace(".Tests.ps1", ".psm1")
    Import-Module -Name $modulePath -Force
    # Get-Module -Name "Module1" | Remove-Module -Force
    # Import-Module (Join-Path $PSScriptRoot "Module1.psm1") -Force
}

Describe "Internal functions" {
    Get-Module TestModule | Remove-Module
    New-Module -Name TestModule {
        function Test-Function {
            <#
        .SYNOPSIS
        This function is used to test the Test-Function.

        .DESCRIPTION
        The Test-Function is used for testing purposes.

        .PARAMETER None
        This function does not accept any parameters.

        .EXAMPLE
        Test-Function
        Outputs "Test-Function" to the console.

        #>
            Write-Output "Test-Function"
        }
        Export-ModuleMember -Function "Test-Function"

        function Test-FunctionInternal {
            Write-Output "Test-FunctionInternal"
        }
    } | Import-Module -Force

    Context "Test-Function" {
        It "The Test-Function function should exist" {
            { Get-Command Test-Function -ErrorAction Stop } | Should -Not -Throw
        }

        It "Returns 'Test-Function'" {
            Test-Function | Should -Be "Test-Function"
        }
    }
    Context "Test-FunctionInternal" {
        It "The Test-FunctionInternal function should not exist" {
            { Get-Command Test-FunctionInternal -ErrorAction Stop } | Should -Throw
        }
        InModuleScope -ModuleName "TestModule" {
            It "The Test-FunctionInternal function should exist" {
                { Get-Command Test-FunctionInternal -ErrorAction Stop } | Should -Not -Throw
            }

            It "Returns 'Test-FunctionInternal'" {
                Test-FunctionInternal | Should -Be "Test-FunctionInternal"
            }
        }
    }

    AfterAll {
        Remove-Module TestModule -Force
    }
}

Describe "Get-HelloWorld" {
    It "The Get-HelloWorld function should exist" {
        { Get-Command -Name Get-HelloWorld -ErrorAction Stop } | Should -Not -Throw
    }

    It "Returns 'Hello World'" {
        Get-HelloWorld | Should -Be "Hello World"
    }
}

Describe "Get-InternalHelloWorld" {
    It "The Get-InternalHelloWorld function should not exist" {
        { Get-Command -Name Get-InternalHelloWorld -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The Get-InternalHelloWorld function should exist" {
            { Get-Command -Name Get-InternalHelloWorld -ErrorAction Stop } | Should -Not -Throw
        }

        It "Returns 'Internal Hello World'" {
            Get-InternalHelloWorld | Should -Be "Internal Hello World"
        }
    }
}

Describe "Test-IsWindowsAdmin" {
    It "The Test-IsWindowsAdmin function should not exist" {
        { Get-Command -Name Test-IsWindowsAdmin -ErrorAction Stop } | Should -Throw
    }

    InModuleScope -ModuleName "Module1" {
        It "The Test-IsWindowsAdmin internal function should exist" {
            { Get-Command -Name Test-IsWindowsAdmin -ErrorAction Stop } | Should -Not -Throw
        }

        It "When running the Test-IsWindowsAdmin internal function without administrator privileges" {
            if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Test-IsWindowsAdmin | Should -BeTrue
            } else {
                Test-IsWindowsAdmin | Should -BeFalse
            }
        }
    }
}

Describe "Start-ServiceWithRetry" {
    It "The Start-ServiceWithRetry function should exist" {
        { Get-Command -Name Start-ServiceWithRetry -ErrorAction Stop } | Should -Not -Throw
    }

    It "Has a <parameter> parameter" -TestCases @(
        @{ Parameter = "ServiceName" }
        @{ Parameter = "MaxRetries" }
    ) {
        Get-Command -Name Start-ServiceWithRetry | Should -HaveParameter -ParameterName $parameter
    }

    It "Has a mandatory ServiceName parameter" {
        Get-Command -Name Start-ServiceWithRetry | Should -HaveParameter -ParameterName ServiceName -Mandatory
    }

    It "Does not throw an error when the ServiceName parameter is provided and the user is an admin" {
        # $inModuleName = (Split-Path -Path $PSCommandPath -Leaf).Replace(".Tests.ps1", "")
        # InModuleScope -ModuleName $inModuleName {
        InModuleScope -ModuleName "Module1" {
            Mock Test-IsWindowsAdmin { return $true }
            Mock Get-Service { return @{ Status = "Running" } }

            { Start-ServiceWithRetry -ServiceName "Service.exe" -MaxRetries 1 } | Should -Not -Throw

            Should -Invoke Test-IsWindowsAdmin -Exactly 1 -Scope It
            Should -Invoke Get-Service -Exactly 1 -Scope It
        }
    }
}

Describe "Update-System" {
    It "The Update-System function should exist" {
        { Get-Command -Name Update-System -ErrorAction Stop } | Should -Not -Throw
    }

    It "Has an Update parameter" {
        Get-Command -Name Update-System | Should -HaveParameter -ParameterName Update
    }

    Context "Testing Update-System function with mocked tests" {
        InModuleScope -ModuleName "Module1" {
            BeforeEach {
                Mock -CommandName Test-IsWindowsAdmin -MockWith { return $true }
                Mock -CommandName Get-WindowsUpdate -MockWith { return @() }
            }
            It "Returns no updates if Get-WindowsUpdate returns no updates" {
                Update-System -Update "WindowsUpdate" | Should -Be "No updates available for WindowsUpdate."

                Should -Invoke -CommandName Test-IsWindowsAdmin -Exactly 1 -Scope It
                Should -Invoke -CommandName Get-WindowsUpdate -Exactly 1 -Scope It
            }

            # It "Returns updates if Get-WindowsUpdate returns updates" {
            #     Mock -CommandName Get-WindowsUpdate -MockWith { return @("Update1") }
            #     Mock -CommandName Install-WindowsUpdate -MockWith {}

            #     Update-System -Update "WindowsUpdate" | Should -BeNullOrEmpty

            #     Should -Invoke -CommandName Test-IsWindowsAdmin -Exactly 1 -Scope It
            #     Should -Invoke -CommandName Get-WindowsUpdate -Exactly 1 -Scope It
            #     Should -Invoke -CommandName Install-WindowsUpdate -Exactly 1 -Scope It
            # }
        }
    }
}

Describe "Install-WindowsGsudo" {
    It "The Install-WindowsGsudo function should not exist" {
        { Get-Command -Name Install-WindowsGsudo -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The Install-WindowsGsudo function should exist" {
            { Get-Command -Name Install-WindowsGsudo -ErrorAction Stop } | Should -Not -Throw
        }

        It "Has a mandatory gsudoPath parameter" {
            Get-Command -Name Install-WindowsGsudo | Should -HaveParameter -ParameterName gsudoPath -Mandatory
        }

        It "Does not throw an error when the gsudoPath parameter is provided" {
            Mock Test-Path { return $false }
            Mock winget {}

            { Install-WindowsGsudo -gsudoPath "Path\gsudo.exe" } | Should -Not -Throw

            Should -Invoke Test-Path -Exactly 1 -Scope It
        }
    }
}

Describe "Install-WindowsOpenSSHClient" {
    It "The Install-WindowsOpenSSHClient function should not exist" {
        { Get-Command -Name Install-WindowsOpenSSHClient -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The Install-WindowsOpenSSHClient function should exist" {
            { Get-Command -Name Install-WindowsOpenSSHClient -ErrorAction Stop } | Should -Not -Throw
        }

        It "Has a mandatory SshPath parameter" {
            Get-Command -Name Install-WindowsOpenSSHClient | Should -HaveParameter -ParameterName SshPath -Mandatory
        }

        It "Does not throw an error when the SshPath parameter is provided as an administrator" {
            Mock Test-Path { return $false }
            Mock Test-IsWindowsAdmin { return $true }
            Mock Add-WindowsCapability {}

            { Install-WindowsOpenSSHClient -SshPath "Path\ssh.exe" } | Should -Not -Throw

            Should -Invoke Test-Path -Exactly 1 -Scope It
            Should -Invoke Test-IsWindowsAdmin -Exactly 1 -Scope It
            Should -Invoke Add-WindowsCapability -Exactly 1 -Scope It
        }
    }
}

Describe "Install-WindowsNmap" {
    It "The Install-WindowsNmap function should not exist" {
        { Get-Command -Name Install-WindowsNmap -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The Install-WindowsNmap function should exist" {
            { Get-Command -Name Install-WindowsNmap -ErrorAction Stop } | Should -Not -Throw
        }

        It "Has a mandatory ncatPath parameter" {
            Get-Command -Name Install-WindowsNmap | Should -HaveParameter -ParameterName ncatPath -Mandatory
        }

        It "Does not throw an error when the ncatPath parameter is provided" {
            Mock Test-Path { return $false }
            Mock winget {}

            { Install-WindowsNmap -ncatPath "Path\ncat.exe" } | Should -Not -Throw

            Should -Invoke Test-Path -Exactly 1 -Scope It
        }
    }
}

Describe "New-DirectoryIfNotExist" {
    It "The New-DirectoryIfNotExist function should not exist" {
        { Get-Command -Name New-DirectoryIfNotExist -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The New-DirectoryIfNotExist function should exist" {
            { Get-Command -Name New-DirectoryIfNotExist -ErrorAction Stop } | Should -Not -Throw
        }

        Context "New-DirectoryIfNotExist function parameters" {
            It "Has a <parameter> parameter" -TestCases @(
                @{ Parameter = "Path" }
                @{ Parameter = "ChildPath" }
            ) {
                Get-Command -Name New-DirectoryIfNotExist | Should -HaveParameter -ParameterName $parameter
            }

            It "Has a Mandatory Path parameter" {
                Get-Command -Name New-DirectoryIfNotExist | Should -HaveParameter -ParameterName Path -Mandatory
            }
        }

        Context "Testing New-DirectoryIfNotExist function with mocked tests" {
            It "Works without ChildPath parameter" {
                Mock Test-Path { return $false }
                Mock New-Item { return [System.IO.DirectoryInfo]::new($env:TEMP) }

                $test = New-DirectoryIfNotExist -Path $env:TEMP
                $test.FullName | Should -Be $env:TEMP

                Should -Invoke Test-Path -Exactly 1 -Scope It
                Should -Invoke New-Item -Exactly 1 -Scope It
            }

            It "The .testDir directory exist before running the function" {
                Mock Test-Path { return $true }
                Mock Get-Item { return [System.IO.DirectoryInfo]::new($env:TEMP + "\.testDir") }

                $test = New-DirectoryIfNotExist -Path $env:TEMP -ChildPath ".testDir"
                $test.FullName | Should -Be $(Join-Path $env:TEMP ".testDir")

                Should -Invoke Test-Path -Exactly 1 -Scope It
                Should -Invoke Get-Item -Exactly 1 -Scope It
            }

            It "The .testDir directory is created if it did not exist before running the function" {
                Mock Test-Path { return $false }
                Mock New-Item { return [System.IO.DirectoryInfo]::new($env:TEMP + "\.testDir") }

                $test = New-DirectoryIfNotExist -Path $env:TEMP -ChildPath ".testDir"
                $test.FullName | Should -Be $(Join-Path $env:TEMP ".testDir")

                Should -Invoke Test-Path -Exactly 1 -Scope It
                Should -Invoke New-Item -Exactly 1 -Scope It
            }

            It "The .ChildDir directory is created if it did not exist before running the function" {
                Mock Test-Path { return $false }
                Mock New-Item { return [System.IO.DirectoryInfo]::new($env:TEMP + "\.testDir\.ChildDir") }
                $testDir = [System.IO.DirectoryInfo]::new($env:TEMP + "\.testDir")

                $test = New-DirectoryIfNotExist -Path $testDir.FullName -ChildPath ".ChildDir"
                $test.FullName | Should -Be $(Join-Path $($env:TEMP + "\.testDir") ".ChildDir")

                Should -Invoke Test-Path -Exactly 1 -Scope It
                Should -Invoke New-Item -Exactly 1 -Scope It
            }
        }

        Context "Testing New-DirectoryIfNotExist function with real tests" {
            BeforeEach {
                $testDir = Join-Path -Path $env:TEMP -ChildPath ".testDir"
                $testDir | Should -Not -BeNullOrEmpty
            }

            AfterEach {
                if (Test-Path $testDir) {
                    Remove-Item -Path $testDir -Recurse -Force
                }
            }

            It "The .testDir directory exist before running the function" {
                $testDir = New-Item -Path $env:TEMP -Name ".testDir" -ItemType Directory
                $testDir | Should -Not -BeNullOrEmpty

                $test = New-DirectoryIfNotExist -Path $env:TEMP -ChildPath ".testDir"
                $test.FullName | Should -Be $(Join-Path $env:TEMP ".testDir")
            }

            It "The .testDir directory is created if it did not exist before running the function" {
                $test = New-DirectoryIfNotExist -Path $env:TEMP -ChildPath ".testDir"
                $test.FullName | Should -Be $(Join-Path $env:TEMP ".testDir")
            }

            It "The .ChildDir directory is created if it did not exist before running the function" {
                $test = New-DirectoryIfNotExist -Path $testDir -ChildPath ".ChildDir"
                $test.FullName | Should -Be $(Join-Path $testDir ".ChildDir")
                Test-Path $(Join-Path $testDir ".ChildDir") | Should -BeTrue
            }
        }
    }
}

Describe "Set-Permission" {
    It "The Set-Permission function should not exist" {
        { Get-Command -Name Set-Permission -ErrorAction Stop } | Should -Throw
    }
    InModuleScope -ModuleName "Module1" {
        It "The Set-Permission function should exist" {
            { Get-Command -Name Set-Permission -ErrorAction Stop } | Should -Not -Throw
        }

        It "Has a <parameter> parameter" -TestCases @(
            @{ Parameter = "Item" }
            @{ Parameter = "IdentityReference" }
            @{ Parameter = "FileSystemRights" }
            @{ Parameter = "AccessControlType" }
        ) {
            Get-Command -Name Set-Permission | Should -HaveParameter -ParameterName $parameter -Mandatory
        }

        Context "Set-Permission functions should exist" {

            BeforeEach {
                $tempFile = New-TemporaryFile
                $tempFile | Should -Not -BeNullOrEmpty
            }

            It "Sets the permissions correctly" {
                Set-Permission -Item $tempFile.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow"
                $acl = Get-Acl -Path $tempFile.FullName
                $accessRule = $acl.Access | Where-Object { $_.IdentityReference -eq "$env:USERDOMAIN\$env:USERNAME" -and $_.IsInherited -eq $false }
                $accessRule.FileSystemRights | Should -Be "FullControl"
                $accessRule.AccessControlType | Should -Be "Allow"
            }

            It "Throws an error for non-existent item" {
                { Set-Permission -Item "NonExistentPath" -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "Allow" -ErrorAction SilentlyContinue } | Should -Throw
            }

            It "Throws an error for invalid FileSystemRights" {
                { Set-Permission -Item $tempFile.FullName -IdentityReference $env:USERNAME -FileSystemRights "InvalidRights" -AccessControlType "Allow" } | Should -Throw
            }

            It "Throws an error for invalid AccessControlType" {
                { Set-Permission -Item $tempFile.FullName -IdentityReference $env:USERNAME -FileSystemRights "FullControl" -AccessControlType "InvalidType" } | Should -Throw
            }

            AfterEach {
                if (Test-Path $tempFile.FullName) {
                    Remove-Item -Path $tempFile.FullName -Force
                }
            }
        }
    }
}

Describe "Set-SSHKeyPasswordProtected" {
    It "The Set-SSHKeyPasswordProtected function should exist" {
        { Get-Command -Name Set-SSHKeyPasswordProtected -ErrorAction Stop } | Should -Not -Throw
    }

    It "Has a <parameter> parameter" -TestCases @(
        @{ Parameter = "RemoteHost" }
        @{ Parameter = "RemoteUser" }
        @{ Parameter = "Keytype" }
        @{ Parameter = "Comment" }
    ) {
        Get-Command -Name Set-SSHKeyPasswordProtected | Should -HaveParameter -ParameterName $parameter
    }

    # Context "Ssh functions should exist" {
    #     InModuleScope -ModuleName "Module1" {
    #     }
    # }
}

Describe "Set-SSHKeyPasswordless" {
    It "The Set-SSHKeyPasswordless function should exist" {
        { Get-Command -Name Set-SSHKeyPasswordless -ErrorAction Stop } | Should -Not -Throw
    }

    It "Has a <parameter> parameter" -TestCases @(
        @{ Parameter = "RemoteHost" }
        @{ Parameter = "RemoteUser" }
        @{ Parameter = "Keytype" }
        @{ Parameter = "Comment" }
    ) {
        Get-Command -Name Set-SSHKeyPasswordless | Should -HaveParameter -ParameterName $parameter
    }

    # Context "Ssh functions should exist" {
    #     InModuleScope -ModuleName "Module1" {
    #     }
    # }
}
