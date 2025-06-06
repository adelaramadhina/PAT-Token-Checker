param(
    [Parameter(Mandatory=$true)][string]$PAT,
    [Parameter(Mandatory=$true)][string]$Organization,
    [Parameter(Mandatory=$false)][string]$Project = $null,
    [Parameter(Mandatory=$false)][string]$OutputPath = "."
)

$ErrorActionPreference = "Continue"
$headers = @{
    Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PAT"))
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$findings = @{
    PATOwner = $null
    AccessibleProjects = @()
    RepositoryAccess = @()
    ServiceConnections = @()
    PipelineAccess = @()
    VariableGroups = @()
    SecretScanning = @()
    BuildHistory = @()
    UserEnumeration = @()
    HighRiskFindings = @()
}

function Invoke-SafeRestMethod {
    param($Uri, $Headers, $Method = "GET")
    try {
        $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method
        return @{ Success = $true; Data = $response; Error = $null }
    }
    catch {
        return @{ Success = $false; Data = $null; Error = $_.Exception.Message }
    }
}

Write-Host "PAT SECURITY ASSESSMENT" -ForegroundColor Green
Write-Host "======================" -ForegroundColor Green
Write-Host "Organization: " -NoNewline
Write-Host $Organization
Write-Host "Timestamp: " -NoNewline
Write-Host (Get-Date)
Write-Host ""

# [1] PAT Owner
Write-Host "[1] IDENTIFYING PAT OWNER AND PERMISSIONS" -ForegroundColor Yellow
$profileUrl = "https://dev.azure.com/" + $Organization + "/_apis/profile/profiles/me?api-version=7.1-preview.3"
$profileResult = Invoke-SafeRestMethod -Uri $profileUrl -Headers $headers

if ($profileResult.Success) {
    $findings.PATOwner = @{
        DisplayName = $profileResult.Data.displayName
        EmailAddress = $profileResult.Data.emailAddress
        Id = $profileResult.Data.id
    }
    Write-Host "PAT Owner: " -NoNewline -ForegroundColor Green
    Write-Host $profileResult.Data.displayName -NoNewline -ForegroundColor Green
    Write-Host " - " -NoNewline -ForegroundColor Green
    Write-Host $profileResult.Data.emailAddress -ForegroundColor Green
} else {
    Write-Host "Could not identify PAT owner: " -NoNewline -ForegroundColor Red
    Write-Host $profileResult.Error -ForegroundColor Red
}

Write-Host ""

# [2] Project Access
Write-Host "[2] ENUMERATING PROJECT ACCESS" -ForegroundColor Yellow
$projectUrl = "https://dev.azure.com/" + $Organization + "/_apis/projects?api-version=7.1"
$projectResult = Invoke-SafeRestMethod -Uri $projectUrl -Headers $headers

if ($projectResult.Success) {
    if ($Project) {
        $filteredProjects = $projectResult.Data.value | Where-Object { $_.name -eq $Project }
        if ($filteredProjects.Count -eq 0) {
            Write-Host "Project not found: " -NoNewline -ForegroundColor Red
            Write-Host $Project -ForegroundColor Red
            exit 1
        }
        $findings.AccessibleProjects = $filteredProjects | ForEach-Object {
            @{
                Name = $_.name
                Id = $_.id
                Visibility = $_.visibility
                State = $_.state
            }
        }
        Write-Host "Targeting specific project: " -NoNewline -ForegroundColor Green
        Write-Host $Project -ForegroundColor Green
    } else {
        $findings.AccessibleProjects = $projectResult.Data.value | ForEach-Object {
            @{
                Name = $_.name
                Id = $_.id
                Visibility = $_.visibility
                State = $_.state
            }
        }
        Write-Host "Access to " -NoNewline -ForegroundColor Green
        Write-Host $findings.AccessibleProjects.Count -NoNewline -ForegroundColor Green
        Write-Host " project(s):" -ForegroundColor Green
        
        foreach ($proj in $findings.AccessibleProjects) {
            Write-Host "  - " -NoNewline -ForegroundColor Cyan
            Write-Host $proj.Name -NoNewline -ForegroundColor Cyan
            Write-Host " - " -NoNewline -ForegroundColor Cyan
            Write-Host $proj.Visibility -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "Could not enumerate projects: " -NoNewline -ForegroundColor Red
    Write-Host $projectResult.Error -ForegroundColor Red
}

Write-Host ""

# [3] Repository Access  
Write-Host "[3] ANALYSING REPOSITORY ACCESS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $projName = $proj.Name
    $repoUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/git/repositories?api-version=7.1"
    $repoResult = Invoke-SafeRestMethod -Uri $repoUrl -Headers $headers
    
    if ($repoResult.Success -and $repoResult.Data.value) {
        foreach ($repo in $repoResult.Data.value) {
            $repoId = $repo.id
            $pushUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/git/repositories/" + $repoId + "/pushes?api-version=7.1&top=1"
            $pushResult = Invoke-SafeRestMethod -Uri $pushUrl -Headers $headers
            
            $repoInfo = @{
                ProjectName = $projName
                RepoName = $repo.name
                RepoId = $repoId
                DefaultBranch = $repo.defaultBranch
                CanReadPushes = $pushResult.Success
                PotentialWriteAccess = $pushResult.Success
            }
            $findings.RepositoryAccess += $repoInfo
            
            if ($pushResult.Success) {
                Write-Host "  " -NoNewline
                Write-Host $projName -NoNewline -ForegroundColor Red
                Write-Host "/" -NoNewline -ForegroundColor Red
                Write-Host $repo.name -NoNewline -ForegroundColor Red
                Write-Host " - READ/POTENTIAL WRITE access" -ForegroundColor Red
                $riskMessage = "Repository write access: " + $projName + "/" + $repo.name
                $findings.HighRiskFindings += $riskMessage
            } else {
                Write-Host "  " -NoNewline
                Write-Host $projName -NoNewline -ForegroundColor Green
                Write-Host "/" -NoNewline -ForegroundColor Green
                Write-Host $repo.name -NoNewline -ForegroundColor Green
                Write-Host " - READ access only" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""

# [4] Service Connections
Write-Host "[4] ENUMERATING SERVICE CONNECTIONS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $projName = $proj.Name
    $scUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
    $scResult = Invoke-SafeRestMethod -Uri $scUrl -Headers $headers
    
    if ($scResult.Success -and $scResult.Data.value) {
        foreach ($sc in $scResult.Data.value) {
            $scInfo = @{
                ProjectName = $projName
                ConnectionName = $sc.name
                ConnectionType = $sc.type
                Url = $sc.url
                IsShared = $sc.isShared
            }
            $findings.ServiceConnections += $scInfo
            
            if ($sc.type -match "azurerm|aws|github|dockerregistry|kubernetes") {
                Write-Host "  HIGH RISK: " -NoNewline -ForegroundColor Red
                Write-Host $sc.name -NoNewline -ForegroundColor Red
                Write-Host " - " -NoNewline -ForegroundColor Red
                Write-Host $sc.type -NoNewline -ForegroundColor Red
                Write-Host " in " -NoNewline -ForegroundColor Red
                Write-Host $projName -ForegroundColor Red
                $riskMessage = "Cloud service connection access: " + $sc.name + " - " + $sc.type
                $findings.HighRiskFindings += $riskMessage
            } else {
                Write-Host "  " -NoNewline
                Write-Host $sc.name -NoNewline -ForegroundColor Yellow
                Write-Host " - " -NoNewline -ForegroundColor Yellow
                Write-Host $sc.type -NoNewline -ForegroundColor Yellow
                Write-Host " in " -NoNewline -ForegroundColor Yellow
                Write-Host $projName -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""

# [5] Pipeline Access
Write-Host "[5] ANALYSING PIPELINE ACCESS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $projName = $proj.Name
    
    # Build Pipelines
    $buildUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/build/definitions?api-version=7.1"
    $buildResult = Invoke-SafeRestMethod -Uri $buildUrl -Headers $headers
    
    if ($buildResult.Success -and $buildResult.Data.value) {
        foreach ($build in $buildResult.Data.value) {
            $pipelineInfo = @{
                ProjectName = $projName
                PipelineName = $build.name
                PipelineType = "Build"
                Path = $build.path
                CanModify = $false
            }
            
            $detailUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/build/definitions/" + $build.id + "?api-version=7.1"
            $detailResult = Invoke-SafeRestMethod -Uri $detailUrl -Headers $headers
            
            if ($detailResult.Success) {
                $pipelineInfo.CanModify = $true
                Write-Host "  Build Pipeline: " -NoNewline -ForegroundColor Red
                Write-Host $build.name -NoNewline -ForegroundColor Red
                Write-Host " - MODIFY ACCESS" -ForegroundColor Red
                $riskMessage = "Pipeline modification access: " + $build.name + " (Build)"
                $findings.HighRiskFindings += $riskMessage
            } else {
                Write-Host "  Build Pipeline: " -NoNewline -ForegroundColor Green
                Write-Host $build.name -NoNewline -ForegroundColor Green
                Write-Host " - READ access" -ForegroundColor Green
            }
            
            $findings.PipelineAccess += $pipelineInfo
        }
    }
    
    # Release Pipelines
    $releaseUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/release/definitions?api-version=7.1-preview.4"
    $releaseResult = Invoke-SafeRestMethod -Uri $releaseUrl -Headers $headers
    
    if ($releaseResult.Success -and $releaseResult.Data.value) {
        foreach ($release in $releaseResult.Data.value) {
            $pipelineInfo = @{
                ProjectName = $projName
                PipelineName = $release.name
                PipelineType = "Release"
                Path = $release.path
                CanModify = $false
            }
            
            $detailUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/release/definitions/" + $release.id + "?api-version=7.1-preview.4"
            $detailResult = Invoke-SafeRestMethod -Uri $detailUrl -Headers $headers
            
            if ($detailResult.Success) {
                $pipelineInfo.CanModify = $true
                Write-Host "  Release Pipeline: " -NoNewline -ForegroundColor Red
                Write-Host $release.name -NoNewline -ForegroundColor Red
                Write-Host " - MODIFY ACCESS" -ForegroundColor Red
                $riskMessage = "Pipeline modification access: " + $release.name + " (Release)"
                $findings.HighRiskFindings += $riskMessage
            } else {
                Write-Host "  Release Pipeline: " -NoNewline -ForegroundColor Green
                Write-Host $release.name -NoNewline -ForegroundColor Green
                Write-Host " - READ access" -ForegroundColor Green
            }
            
            $findings.PipelineAccess += $pipelineInfo
        }
    }
}

Write-Host ""

# [6] Variable Groups
Write-Host "[6] ANALYSING VARIABLE GROUPS AND SECRETS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $projName = $proj.Name
    $vgUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/distributedtask/variablegroups?api-version=7.1-preview.2"
    $vgResult = Invoke-SafeRestMethod -Uri $vgUrl -Headers $headers
    
    if ($vgResult.Success -and $vgResult.Data.value) {
        foreach ($vg in $vgResult.Data.value) {
            $secretCount = 0
            $plainCount = 0
            
            if ($vg.variables) {
                foreach ($varName in $vg.variables.PSObject.Properties.Name) {
                    $var = $vg.variables.$varName
                    if ($var.isSecret) {
                        $secretCount++
                    } else {
                        $plainCount++
                        if ($var.value -match "password|token|key|secret|connection|api" -or $var.value.Length -gt 50) {
                            $riskMessage = "Potential secret in plain text: " + $projName + "/" + $vg.name + "/" + $varName
                            $findings.HighRiskFindings += $riskMessage
                        }
                    }
                }
            }
            
            $vgInfo = @{
                ProjectName = $projName
                GroupName = $vg.name
                SecretCount = $secretCount
                PlainVariableCount = $plainCount
            }
            $findings.VariableGroups += $vgInfo
            
            if ($secretCount -gt 0) {
                Write-Host "  " -NoNewline
                Write-Host $projName -NoNewline -ForegroundColor Red
                Write-Host "/" -NoNewline -ForegroundColor Red
                Write-Host $vg.name -NoNewline -ForegroundColor Red
                Write-Host ": " -NoNewline -ForegroundColor Red
                Write-Host $secretCount -NoNewline -ForegroundColor Red
                Write-Host " secret(s), " -NoNewline -ForegroundColor Red
                Write-Host $plainCount -NoNewline -ForegroundColor Red
                Write-Host " plain variables" -ForegroundColor Red
                $riskMessage = "Secret access in variable group: " + $projName + "/" + $vg.name
                $findings.HighRiskFindings += $riskMessage
            } else {
                Write-Host "  " -NoNewline
                Write-Host $projName -NoNewline -ForegroundColor Green
                Write-Host "/" -NoNewline -ForegroundColor Green
                Write-Host $vg.name -NoNewline -ForegroundColor Green
                Write-Host ": " -NoNewline -ForegroundColor Green
                Write-Host $plainCount -NoNewline -ForegroundColor Green
                Write-Host " plain variables" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""

# [7] Code Scanning
Write-Host "[7] SCANNING FOR SECRETS IN CODE" -ForegroundColor Yellow
if ($Project) {
    $reposToScan = $findings.RepositoryAccess
} else {
    $reposToScan = $findings.RepositoryAccess | Select-Object -First 5
}

foreach ($repo in $reposToScan) {
    $searchUrl = "https://dev.azure.com/" + $Organization + "/_apis/search/codesearchresults?api-version=7.1-preview.1"
    $searchBodyJson = @{
        searchText = "password OR token OR api_key OR secret OR connectionstring"
        '$filter' = "Repository:" + $repo.RepoName + " AND Project:" + $repo.ProjectName
        '$top' = 10
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri $searchUrl -Headers $headers -Method "POST" -Body $searchBodyJson -ContentType "application/json"
        if ($response.results) {
            foreach ($result in $response.results) {
                $secretInfo = @{
                    Repository = $repo.RepoName
                    Project = $repo.ProjectName
                    FileName = $result.fileName
                    CodeSnippet = $result.contentMatch
                }
                $findings.SecretScanning += $secretInfo
            }
            Write-Host "  Found potential secrets in " -NoNewline -ForegroundColor Yellow
            Write-Host $repo.ProjectName -NoNewline -ForegroundColor Yellow
            Write-Host "/" -NoNewline -ForegroundColor Yellow
            Write-Host $repo.RepoName -ForegroundColor Yellow
            $riskMessage = "Potential secrets in code: " + $repo.ProjectName + "/" + $repo.RepoName
            $findings.HighRiskFindings += $riskMessage
        }
    }
    catch {
        # Code search may not be enabled - skip silently
    }
}

Write-Host ""

# [8] Build History
Write-Host "[8] CHECKING BUILD HISTORY AND ARTIFACTS" -ForegroundColor Yellow
if ($Project) {
    $projectsToCheck = $findings.AccessibleProjects
} else {
    $projectsToCheck = $findings.AccessibleProjects | Select-Object -First 3
}

foreach ($proj in $projectsToCheck) {
    $projName = $proj.Name
    $buildHistoryUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/build/builds?api-version=7.1&top=10"
    $buildHistoryResult = Invoke-SafeRestMethod -Uri $buildHistoryUrl -Headers $headers
    
    if ($buildHistoryResult.Success -and $buildHistoryResult.Data.value) {
        foreach ($build in $buildHistoryResult.Data.value) {
            $buildId = $build.id
            $logUrl = "https://dev.azure.com/" + $Organization + "/" + $projName + "/_apis/build/builds/" + $buildId + "/logs?api-version=7.1"
            $logResult = Invoke-SafeRestMethod -Uri $logUrl -Headers $headers
            
            $buildInfo = @{
                ProjectName = $projName
                BuildNumber = $build.buildNumber
                Status = $build.status
                CanAccessLogs = $logResult.Success
                StartTime = $build.startTime
            }
            $findings.BuildHistory += $buildInfo
            
            if ($logResult.Success) {
                Write-Host "  Can access build logs: " -NoNewline -ForegroundColor Yellow
                Write-Host $projName -NoNewline -ForegroundColor Yellow
                Write-Host " - Build " -NoNewline -ForegroundColor Yellow
                Write-Host $build.buildNumber -ForegroundColor Yellow
                $riskMessage = "Build log access: " + $projName + " - Build " + $build.buildNumber
                $findings.HighRiskFindings += $riskMessage
            }
        }
    }
}

Write-Host ""

# [9] User Enumeration
Write-Host "[9] USER ENUMERATION" -ForegroundColor Yellow
$userUrl = "https://dev.azure.com/" + $Organization + "/_apis/graph/users?api-version=7.1-preview.1"
$userResult = Invoke-SafeRestMethod -Uri $userUrl -Headers $headers

if ($userResult.Success -and $userResult.Data.value) {
    $findings.UserEnumeration = $userResult.Data.value | ForEach-Object {
        @{
            DisplayName = $_.displayName
            MailAddress = $_.mailAddress
            PrincipalName = $_.principalName
            Origin = $_.origin
        }
    }
    Write-Host "Enumerated " -NoNewline -ForegroundColor Yellow
    Write-Host $findings.UserEnumeration.Count -NoNewline -ForegroundColor Yellow
    Write-Host " user accounts" -ForegroundColor Yellow
    $riskMessage = "User enumeration: " + $findings.UserEnumeration.Count + " accounts discovered"
    $findings.HighRiskFindings += $riskMessage
} else {
    Write-Host "Could not enumerate users: " -NoNewline -ForegroundColor Red
    Write-Host $userResult.Error -ForegroundColor Red
}

Write-Host ""

# Summary
Write-Host "SECURITY ASSESSMENT SUMMARY" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "===========================" -ForegroundColor Red

if ($findings.PATOwner) {
    Write-Host "PAT Owner: " -NoNewline -ForegroundColor White
    Write-Host $findings.PATOwner.DisplayName -NoNewline -ForegroundColor White
    Write-Host " - " -NoNewline -ForegroundColor White
    Write-Host $findings.PATOwner.EmailAddress -ForegroundColor White
} else {
    Write-Host "PAT Owner: Unknown" -ForegroundColor White
}

Write-Host "Projects Accessible: " -NoNewline -ForegroundColor White
Write-Host $findings.AccessibleProjects.Count -ForegroundColor White
Write-Host "Repositories with Access: " -NoNewline -ForegroundColor White
Write-Host $findings.RepositoryAccess.Count -ForegroundColor White
Write-Host "Service Connections Found: " -NoNewline -ForegroundColor Yellow
Write-Host $findings.ServiceConnections.Count -ForegroundColor Yellow
Write-Host "Pipelines Accessible: " -NoNewline -ForegroundColor White
Write-Host $findings.PipelineAccess.Count -ForegroundColor White
Write-Host "Variable Groups: " -NoNewline -ForegroundColor Yellow
Write-Host $findings.VariableGroups.Count -ForegroundColor Yellow
Write-Host "Users Enumerated: " -NoNewline -ForegroundColor Yellow
Write-Host $findings.UserEnumeration.Count -ForegroundColor Yellow

Write-Host ""
Write-Host "HIGH-RISK FINDINGS:" -ForegroundColor Red
foreach ($risk in $findings.HighRiskFindings) {
    Write-Host "  " -NoNewline
    Write-Host $risk -ForegroundColor Red
}

# Create output
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: " -NoNewline -ForegroundColor Green
    Write-Host $OutputPath -ForegroundColor Green
}

$reportFileName = "PAT_Security_Assessment_" + $Organization + "_" + $timestamp + ".json"
$reportPath = Join-Path $OutputPath $reportFileName
$findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8

# Create summary file
$summaryFileName = "PAT_Summary_" + $Organization + "_" + $timestamp + ".txt"
$summaryPath = Join-Path $OutputPath $summaryFileName

$summaryLines = @()
$summaryLines += "PAT SECURITY ASSESSMENT SUMMARY"
$summaryLines += "==============================="
$summaryLines += "Organisation: " + $Organization
$summaryLines += "Assessment Date: " + (Get-Date)

if ($findings.PATOwner) {
    $ownerLine = "PAT Owner: " + $findings.PATOwner.DisplayName + " - " + $findings.PATOwner.EmailAddress
    $summaryLines += $ownerLine
} else {
    $summaryLines += "PAT Owner: Unknown"
}

$summaryLines += ""
$summaryLines += "SUMMARY:"
$summaryLines += "Projects Accessible: " + $findings.AccessibleProjects.Count
$summaryLines += "Repositories with Access: " + $findings.RepositoryAccess.Count
$summaryLines += "Service Connections Found: " + $findings.ServiceConnections.Count
$summaryLines += "Pipelines Accessible: " + $findings.PipelineAccess.Count
$summaryLines += "Variable Groups: " + $findings.VariableGroups.Count
$summaryLines += "Users Enumerated: " + $findings.UserEnumeration.Count
$summaryLines += ""
$summaryLines += "HIGH-RISK FINDINGS - " + $findings.HighRiskFindings.Count + " total:"
$findings.HighRiskFindings | ForEach-Object { $summaryLines += $_ }
$summaryLines += ""
$detailsFile = "PAT_Security_Assessment_" + $Organization + "_" + $timestamp + ".json"
$summaryLines += "For detailed technical information, see: " + $detailsFile

$summaryContent = $summaryLines -join "`r`n"
$summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Reports Generated:" -ForegroundColor Green
Write-Host "Technical Details: " -NoNewline -ForegroundColor Green
Write-Host $reportPath -ForegroundColor Green
Write-Host "Summary: " -NoNewline -ForegroundColor Green
Write-Host $summaryPath -ForegroundColor Green
