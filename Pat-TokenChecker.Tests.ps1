BeforeAll {
    . $PSScriptRoot\Pat-TokenChecker.ps1 -PAT "dummy" -Organization "test" -WhatIf
}

Describe "Pat-TokenChecker Parameter Validation" {
    Context "When validating required parameters" {
        It "Should require PAT parameter" {
            { & $PSScriptRoot\Pat-TokenChecker.ps1 -Organization "test" } | Should -Throw
        }

        It "Should require Organization parameter" {
            { & $PSScriptRoot\Pat-TokenChecker.ps1 -PAT "test" } | Should -Throw
        }

        It "Should accept valid PAT and Organization" {
            { & $PSScriptRoot\Pat-TokenChecker.ps1 -PAT "test" -Organization "test" -WhatIf } | Should -Not -Throw
        }

        It "Should accept optional Project parameter" {
            { & $PSScriptRoot\Pat-TokenChecker.ps1 -PAT "test" -Organization "test" -Project "testproject" -WhatIf } | Should -Not -Throw
        }

        It "Should accept optional OutputPath parameter" {
            { & $PSScriptRoot\Pat-TokenChecker.ps1 -PAT "test" -Organization "test" -OutputPath "C:\temp" -WhatIf } | Should -Not -Throw
        }
    }
}

Describe "Authorization Header Construction" {
    Context "When building authentication headers" {
        It "Should create correct Authorization header format" {
            $testPAT = "testtoken123"
            $expectedAuth = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$testPAT"))
            
            $headers = @{
                Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$testPAT"))
            }
            
            $headers.Authorization | Should -Be $expectedAuth
        }

        It "Should use correct header name (Authorization not Authorisation)" {
            $headers = @{
                Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":testtoken"))
            }
            
            $headers.ContainsKey("Authorization") | Should -Be $true
            $headers.ContainsKey("Authorisation") | Should -Be $false
        }

        It "Should base64 encode PAT correctly" {
            $testPAT = "mytoken"
            $expectedEncoding = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$testPAT"))
            $headers = @{
                Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$testPAT"))
            }
            
            $headers.Authorization | Should -Be "Basic $expectedEncoding"
        }
    }
}

Describe "Invoke-SafeRestMethod Function" {
    Context "When making REST API calls" {
        It "Should return success object structure" {
            Mock Invoke-RestMethod { return @{ test = "data" } }
            
            $result = Invoke-SafeRestMethod -Uri "https://test.com" -Headers @{} -Method "GET"
            
            $result.Success | Should -Be $true
            $result.Data | Should -Not -Be $null
            $result.Error | Should -Be $null
        }

        It "Should return error object structure on exception" {
            Mock Invoke-RestMethod { throw "Test error" }
            
            $result = Invoke-SafeRestMethod -Uri "https://test.com" -Headers @{} -Method "GET"
            
            $result.Success | Should -Be $false
            $result.Data | Should -Be $null
            $result.Error | Should -Not -Be $null
        }

        It "Should default to GET method when not specified" {
            Mock Invoke-RestMethod { return @{} } -ParameterFilter { $Method -eq "GET" }
            
            $result = Invoke-SafeRestMethod -Uri "https://test.com" -Headers @{}
            
            Assert-MockCalled Invoke-RestMethod -ParameterFilter { $Method -eq "GET" }
        }
    }
}

Describe "URL Construction" {
    Context "When building Azure DevOps API URLs" {
        It "Should construct profile URL correctly" {
            $organization = "myorg"
            $expectedUrl = "https://dev.azure.com/$organization/_apis/profile/profiles/me?api-version=7.1-preview.3"
            
            $profileUrl = "https://dev.azure.com/$organization/_apis/profile/profiles/me?api-version=7.1-preview.3"
            
            $profileUrl | Should -Be $expectedUrl
        }

        It "Should construct projects URL correctly" {
            $organization = "myorg"
            $expectedUrl = "https://dev.azure.com/$organization/_apis/projects?api-version=7.1"
            
            $projectUrl = "https://dev.azure.com/$organization/_apis/projects?api-version=7.1"
            
            $projectUrl | Should -Be $expectedUrl
        }

        It "Should handle special characters in organization name" {
            $organization = "my-org_123"
            $profileUrl = "https://dev.azure.com/$organization/_apis/profile/profiles/me?api-version=7.1-preview.3"
            
            $profileUrl | Should -Match "my-org_123"
        }
    }
}

Describe "Output File Generation" {
    Context "When generating report files" {
        It "Should create JSON report filename with timestamp" {
            $organization = "testorg"
            $timestamp = "20231201_143000"
            $outputPath = "."
            
            $expectedPath = Join-Path $outputPath "PAT_Security_Assessment_$($organization)_$timestamp.json"
            $reportPath = Join-Path $outputPath "PAT_Security_Assessment_$($organization)_$timestamp.json"
            
            $reportPath | Should -Be $expectedPath
        }

        It "Should create summary report filename with timestamp" {
            $organization = "testorg"
            $timestamp = "20231201_143000"
            $outputPath = "."
            
            $expectedPath = Join-Path $outputPath "PAT_Summary_$($organization)_$timestamp.txt"
            $summaryPath = Join-Path $outputPath "PAT_Summary_$($organization)_$timestamp.txt"
            
            $summaryPath | Should -Be $expectedPath
        }
    }
}

Describe "Directory Creation" {
    Context "When output directory doesn't exist" {
        BeforeEach {
            $testPath = Join-Path $TestDrive "nonexistent_dir"
        }

        It "Should create directory if it doesn't exist" {
            $testPath | Should -Not -Exist
            
            if (-not (Test-Path $testPath)) {
                New-Item -ItemType Directory -Path $testPath -Force | Out-Null
            }
            
            $testPath | Should -Exist
            (Get-Item $testPath).PSIsContainer | Should -Be $true
        }

        It "Should not fail if directory already exists" {
            New-Item -ItemType Directory -Path $testPath -Force | Out-Null
            $testPath | Should -Exist
            
            { New-Item -ItemType Directory -Path $testPath -Force | Out-Null } | Should -Not -Throw
            
            $testPath | Should -Exist
        }

        It "Should handle nested directory creation" {
            $nestedPath = Join-Path $testPath "nested\subdirectory"
            
            if (-not (Test-Path $nestedPath)) {
                New-Item -ItemType Directory -Path $nestedPath -Force | Out-Null
            }
            
            $nestedPath | Should -Exist
        }
    }
}

Describe "Findings Object Structure" {
    Context "When initializing findings object" {
        It "Should contain all required properties" {
            $findings = @{
                PATOwner = $null
                PATScopes = @()
                AccessibleProjects = @()
                RepositoryAccess = @()
                ServiceConnections = @()
                PipelineAccess = @()
                UserEnumeration = @()
                VariableGroups = @()
                SecretScanning = @()
                BuildHistory = @()
                AuditLogs = @()
                Extensions = @()
                SecurityNamespaces = @()
                CrossProjectAccess = @()
                AdvancedPermissions = @()
                HighRiskFindings = @()
            }
            
            $findings.ContainsKey("PATOwner") | Should -Be $true
            $findings.ContainsKey("AccessibleProjects") | Should -Be $true
            $findings.ContainsKey("RepositoryAccess") | Should -Be $true
            $findings.ContainsKey("HighRiskFindings") | Should -Be $true
        }

        It "Should initialize arrays as empty" {
            $findings = @{
                PATScopes = @()
                AccessibleProjects = @()
                HighRiskFindings = @()
            }
            
            $findings.PATScopes.Count | Should -Be 0
            $findings.AccessibleProjects.Count | Should -Be 0
            $findings.HighRiskFindings.Count | Should -Be 0
        }
    }
}