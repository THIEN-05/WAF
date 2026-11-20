$ErrorActionPreference = 'Continue'
$missing = $false

function Test-Tool([string]$Name, [string]$DisplayName = $Name) {
    $tool = Get-Command $Name -ErrorAction SilentlyContinue
    if ($tool) {
        Write-Output "OK      ${DisplayName}: $($tool.Source)"
    } else {
        Write-Output "MISSING ${DisplayName}"
        $script:missing = $true
    }
}

Test-Tool 'go' 'Go'
Test-Tool 'docker' 'Docker'
Test-Tool 'make' 'make'
Test-Tool 'gcc' 'gcc'
Test-Tool 'golangci-lint' 'golangci-lint'

if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker compose version *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Output 'OK      Docker Compose'
    } else {
        Write-Output 'MISSING Docker Compose plugin'
        $missing = $true
    }
}

if ($missing) { exit 1 }
exit 0
