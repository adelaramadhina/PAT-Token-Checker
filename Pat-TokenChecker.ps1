param(
    [Parameter(Mandatory=$true)][string]$PAT,
    [Parameter(Mandatory=$true)][string]$Organization,
    [Parameter(Mandatory=$false)][string]$Project = $null,
    [Parameter(Mandatory=$false)][string]$OutputPath = "."
)

$ErrorActionPreference = "Continue"
$amp = "&"
$dtop = "`$top"
$headers = @{
    Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PAT"))
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "PAT SECURITY ASSESSMENT" -ForegroundColor Green
Write-Host "======================" -ForegroundColor Green
Write-Host "Organization: $Organization"
Write-Host "Timestamp: $(Get-Date)"
Write-Host ""

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

Write-Host "[1] IDENTIFYING PAT OWNER AND PERMISSIONS" -ForegroundColor Yellow
$profileUrl = "https://dev.azure.com/$Organization/_apis/profile/profiles/me?api-version=7.1-preview.3"
$profileResult = Invoke-SafeRestMethod -Uri $profileUrl -Headers $headers

if ($profileResult.Success) {
    $findings.PATOwner = @{
        DisplayName = $profileResult.Data.displayName
        EmailAddress = $profileResult.Data.emailAddress
        Id = $profileResult.Data.id
        TimeStamp = $profileResult.Data.timeStamp
    }
    Write-Host "✓ PAT Owner: $($profileResult.Data.displayName) ($($profileResult.Data.emailAddress))" -ForegroundColor Green
} else {
    Write-Host "✗ Could not identify PAT owner: $($profileResult.Error)" -ForegroundColor Red
}

Write-Host ""
Write-Host "[2] ENUMERATING PROJECT ACCESS" -ForegroundColor Yellow
$projectUrl = "https://dev.azure.com/$Organization/_apis/projects?api-version=7.1"
$projectResult = Invoke-SafeRestMethod -Uri $projectUrl -Headers $headers

if ($projectResult.Success) {
    if ($Project) {
        # Filter to specific project
        $filteredProjects = $projectResult.Data.value | Where-Object { $_.name -eq $Project }
        if ($filteredProjects.Count -eq 0) {
            Write-Host "✗ Project '$Project' not found in accessible projects" -ForegroundColor Red
            exit 1
        }
        $findings.AccessibleProjects = $filteredProjects | ForEach-Object {
            @{
                Name = $_.name
                Id = $_.id
                Visibility = $_.visibility
                State = $_.state
                Description = $_.description
            }
        }
        Write-Host "✓ Targeting specific project: $Project" -ForegroundColor Green
    } else {
        # Show all accessible projects
        $findings.AccessibleProjects = $projectResult.Data.value | ForEach-Object {
            @{
                Name = $_.name
                Id = $_.id
                Visibility = $_.visibility
                State = $_.state
                Description = $_.description
            }
        }
        Write-Host "✓ Access to $($findings.AccessibleProjects.Count) project(s):" -ForegroundColor Green
        foreach ($proj in $findings.AccessibleProjects) {
            Write-Host "  - $($proj.Name) ($($proj.Visibility))" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "✗ Could not enumerate projects: $($projectResult.Error)" -ForegroundColor Red
}

Write-Host ""
Write-Host "[3] ANALYSING REPOSITORY ACCESS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $repoUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/git/repositories?api-version=7.1"
    $repoResult = Invoke-SafeRestMethod -Uri $repoUrl -Headers $headers
    
    if ($repoResult.Success -and $repoResult.Data.value) {
        foreach ($repo in $repoResult.Data.value) {
            $pushUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/git/repositories/$($repo.id)/pushes?api-version=7.1$amp$dtop=1"
            $pushResult = Invoke-SafeRestMethod -Uri $pushUrl -Headers $headers
            
            $repoInfo = @{
                ProjectName = $proj.Name
                RepoName = $repo.name
                RepoId = $repo.id
                DefaultBranch = $repo.defaultBranch
                RemoteUrl = $repo.remoteUrl
                Size = $repo.size
                CanReadPushes = $pushResult.Success
                PotentialWriteAccess = $pushResult.Success
            }
            $findings.RepositoryAccess += $repoInfo
            
            if ($pushResult.Success) {
                Write-Host "  ✓ $($proj.Name)/$($repo.name) - READ/POTENTIAL WRITE access" -ForegroundColor Red
                $findings.HighRiskFindings += "Repository write access: $($proj.Name)/$($repo.name)"
            } else {
                Write-Host "  - $($proj.Name)/$($repo.name) - READ access only" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""
Write-Host "[4] ENUMERATING SERVICE CONNECTIONS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $scUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
    $scResult = Invoke-SafeRestMethod -Uri $scUrl -Headers $headers
    
    if ($scResult.Success -and $scResult.Data.value) {
        foreach ($sc in $scResult.Data.value) {
            $scInfo = @{
                ProjectName = $proj.Name
                ConnectionName = $sc.name
                ConnectionType = $sc.type
                Url = $sc.url
                AuthScheme = $sc.Authorisation.scheme
                IsShared = $sc.isShared
                Owner = $sc.owner
            }
            $findings.ServiceConnections += $scInfo
            
            if ($sc.type -match "azurerm|aws|github|dockerregistry|kubernetes") {
                Write-Host "  🚨 HIGH RISK: $($sc.name) ($($sc.type)) in $($proj.Name)" -ForegroundColor Red
                $findings.HighRiskFindings += "Cloud service connection access: $($sc.name) ($($sc.type))"
            } else {
                Write-Host "  - $($sc.name) ($($sc.type)) in $($proj.Name)" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
Write-Host "[5] ANALYSING PIPELINE ACCESS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $buildUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/build/definitions?api-version=7.1"
    $buildResult = Invoke-SafeRestMethod -Uri $buildUrl -Headers $headers
    
    if ($buildResult.Success -and $buildResult.Data.value) {
        foreach ($build in $buildResult.Data.value) {
            $pipelineInfo = @{
                ProjectName = $proj.Name
                PipelineName = $build.name
                PipelineType = "Build"
                Path = $build.path
                Repository = $build.repository.name
                CanModify = $false
            }
            
            $detailUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/build/definitions/$($build.id)?api-version=7.1"
            $detailResult = Invoke-SafeRestMethod -Uri $detailUrl -Headers $headers
            
            if ($detailResult.Success) {
                $pipelineInfo.CanModify = $true
                Write-Host "  ⚠️  Build Pipeline: $($build.name) - MODIFY ACCESS" -ForegroundColor Red
                $findings.HighRiskFindings += "Pipeline modification access: $($build.name) (Build)"
            } else {
                Write-Host "  - Build Pipeline: $($build.name) - READ access" -ForegroundColor Green
            }
            
            $findings.PipelineAccess += $pipelineInfo
        }
    }
    
    $releaseUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/release/definitions?api-version=7.1-preview.4"
    $releaseResult = Invoke-SafeRestMethod -Uri $releaseUrl -Headers $headers
    
    if ($releaseResult.Success -and $releaseResult.Data.value) {
        foreach ($release in $releaseResult.Data.value) {
            $pipelineInfo = @{
                ProjectName = $proj.Name
                PipelineName = $release.name
                PipelineType = "Release"
                Path = $release.path
                Repository = "N/A"
                CanModify = $false
            }
            
            $detailUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/release/definitions/$($release.id)?api-version=7.1-preview.4"
            $detailResult = Invoke-SafeRestMethod -Uri $detailUrl -Headers $headers
            
            if ($detailResult.Success) {
                $pipelineInfo.CanModify = $true
                Write-Host "  ⚠️  Release Pipeline: $($release.name) - MODIFY ACCESS" -ForegroundColor Red
                $findings.HighRiskFindings += "Pipeline modification access: $($release.name) (Release)"
            } else {
                Write-Host "  - Release Pipeline: $($release.name) - READ access" -ForegroundColor Green
            }
            
            $findings.PipelineAccess += $pipelineInfo
        }
    }
}

Write-Host ""
Write-Host "[6] ANALYSING VARIABLE GROUPS AND SECRETS" -ForegroundColor Yellow
foreach ($proj in $findings.AccessibleProjects) {
    $vgUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/distributedtask/variablegroups?api-version=7.1-preview.2"
    $vgResult = Invoke-SafeRestMethod -Uri $vgUrl -Headers $headers
    
    if ($vgResult.Success -and $vgResult.Data.value) {
        foreach ($vg in $vgResult.Data.value) {
            $secretCount = 0
            $sensitiveVars = @()
            $plainVars = @()
            
            if ($vg.variables) {
                foreach ($varName in $vg.variables.PSObject.Properties.Name) {
                    $var = $vg.variables.$varName
                    if ($var.isSecret) {
                        $secretCount++
                        $sensitiveVars += $varName
                    } else {
                        $plainVars += @{Name=$varName; Value=$var.value}
                        if ($var.value -match "password|token|key|secret|connection|api" -or $var.value.Length -gt 50) {
                            $findings.HighRiskFindings += "Potential secret in plain text: $($proj.Name)/$($vg.name)/$varName"
                        }
                    }
                }
            }
            
            $vgInfo = @{
                ProjectName = $proj.Name
                GroupName = $vg.name
                Description = $vg.description
                SecretCount = $secretCount
                PlainVariableCount = $plainVars.Count
                SensitiveVariables = $sensitiveVars
                PlainVariables = $plainVars
            }
            $findings.VariableGroups += $vgInfo
            
            if ($secretCount -gt 0) {
                Write-Host "  🔐 $($proj.Name)/$($vg.name): $secretCount secret(s), $($plainVars.Count) plain variables" -ForegroundColor Red
                $findings.HighRiskFindings += "Secret access in variable group: $($proj.Name)/$($vg.name)"
            } else {
                Write-Host "  - $($proj.Name)/$($vg.name): $($plainVars.Count) plain variables" -ForegroundColor Green
            }
        }
    }
}

Write-Host ""
Write-Host "[7] SCANNING FOR SECRETS IN CODE" -ForegroundColor Yellow
$reposToScan = if ($Project) { $findings.RepositoryAccess } else { $findings.RepositoryAccess | Select-Object -First 5 }
foreach ($repo in $reposToScan) {
    $searchUrl = "https://dev.azure.com/$Organization/_apis/search/codesearchresults?api-version=7.1-preview.1"
    $searchBodyJson = @{
        searchText = "password OR token OR api_key OR secret OR connectionstring"
        '$filter' = "Repository:$($repo.RepoName) AND Project:$($repo.ProjectName)"
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
            Write-Host "  ⚠️  Found potential secrets in $($repo.ProjectName)/$($repo.RepoName)" -ForegroundColor Yellow
            $findings.HighRiskFindings += "Potential secrets in code: $($repo.ProjectName)/$($repo.RepoName)"
        }
    }
    catch {
    }
}

Write-Host ""
Write-Host "[8] CHECKING BUILD HISTORY AND ARTIFACTS" -ForegroundColor Yellow
$projectsToCheck = if ($Project) { $findings.AccessibleProjects } else { $findings.AccessibleProjects | Select-Object -First 3 }
foreach ($proj in $projectsToCheck) {
    $buildHistoryUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/build/builds?api-version=7.1$amp$dtop=10"
    $buildHistoryResult = Invoke-SafeRestMethod -Uri $buildHistoryUrl -Headers $headers
    
    if ($buildHistoryResult.Success -and $buildHistoryResult.Data.value) {
        foreach ($build in $buildHistoryResult.Data.value) {
            $logUrl = "https://dev.azure.com/$Organization/$($proj.Name)/_apis/build/builds/$($build.id)/logs?api-version=7.1"
            $logResult = Invoke-SafeRestMethod -Uri $logUrl -Headers $headers
            
            $buildInfo = @{
                ProjectName = $proj.Name
                BuildNumber = $build.buildNumber
                Status = $build.status
                RequestedBy = $build.requestedBy.displayName
                CanAccessLogs = $logResult.Success
                StartTime = $build.startTime
            }
            $findings.BuildHistory += $buildInfo
            
            if ($logResult.Success) {
                Write-Host "  📋 Can access build logs: $($proj.Name) - Build $($build.buildNumber)" -ForegroundColor Yellow
                $findings.HighRiskFindings += "Build log access: $($proj.Name) - Build $($build.buildNumber)"
            }
        }
    }
}

Write-Host ""
Write-Host "[9] USER ENUMERATION" -ForegroundColor Yellow
$userUrl = "https://dev.azure.com/$Organization/_apis/graph/users?api-version=7.1-preview.1"
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
    Write-Host "✓ Enumerated $($findings.UserEnumeration.Count) user accounts" -ForegroundColor Yellow
    $findings.HighRiskFindings += "User enumeration: $($findings.UserEnumeration.Count) accounts discovered"
} else {
    Write-Host "✗ Could not enumerate users: $($userResult.Error)" -ForegroundColor Red
}

Write-Host ""
Write-Host "SECURITY ASSESSMENT SUMMARY" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "===========================" -ForegroundColor Red
Write-Host "PAT Owner: $($findings.PATOwner.DisplayName) ($($findings.PATOwner.EmailAddress))" -ForegroundColor White
Write-Host "Projects Accessible: $($findings.AccessibleProjects.Count)" -ForegroundColor White
Write-Host "Repositories with Access: $($findings.RepositoryAccess.Count)" -ForegroundColor White
Write-Host "Service Connections Found: $($findings.ServiceConnections.Count)" -ForegroundColor Yellow
Write-Host "Pipelines Accessible: $($findings.PipelineAccess.Count)" -ForegroundColor White
Write-Host "Variable Groups: $($findings.VariableGroups.Count)" -ForegroundColor Yellow
Write-Host "Users Enumerated: $($findings.UserEnumeration.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "HIGH-RISK FINDINGS:" -ForegroundColor Red
foreach ($risk in $findings.HighRiskFindings) {
    Write-Host "  • $risk" -ForegroundColor Red
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
}

$reportPath = Join-Path $OutputPath "PAT_Security_Assessment_$($Organization)_$timestamp.json"
$findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8

$summaryPath = Join-Path $OutputPath "PAT_Summary_$($Organization)_$timestamp.txt"
$summaryContent = @"
PAT SECURITY ASSESSMENT SUMMARY
===============================
Organisation: $Organization
Assessment Date: $(Get-Date)
PAT Owner: $($findings.PATOwner.DisplayName) ($($findings.PATOwner.EmailAddress))

SUMMARY:
- Projects Accessible: $($findings.AccessibleProjects.Count)
- Repositories with Access: $($findings.RepositoryAccess.Count)
- Service Connections Found: $($findings.ServiceConnections.Count)
- Pipelines Accessible: $($findings.PipelineAccess.Count)
- Variable Groups: $($findings.VariableGroups.Count)
- Users Enumerated: $($findings.UserEnumeration.Count)

HIGH-RISK FINDINGS ($($findings.HighRiskFindings.Count) total):
$($findings.HighRiskFindings | ForEach-Object { "• $_" } | Out-String)

For detailed technical information, see: PAT_Security_Assessment_$($Organization)_$timestamp.json
"@

$summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Reports Generated:" -ForegroundColor Green
Write-Host "Technical Details: $reportPath" -ForegroundColor Green
Write-Host "Summary: $summaryPath" -ForegroundColor Green