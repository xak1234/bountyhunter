# Fix Go PATH for bughunter3.py
# This script adds the Go bin directory to the user's PATH permanently

Write-Host "🔧 Fixing Go PATH for bughunter3.py" -ForegroundColor Green
Write-Host "=" * 50

# Get current GOPATH
$gopath = go env GOPATH
$goBinPath = "$gopath\bin"

Write-Host "GOPATH: $gopath"
Write-Host "Go Bin Path: $goBinPath"

# Check if the path already exists in user PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$pathEntries = $userPath -split ';'

if ($pathEntries -contains $goBinPath) {
    Write-Host "✅ Go bin directory is already in user PATH" -ForegroundColor Green
} else {
    Write-Host "⚠️ Go bin directory is NOT in user PATH" -ForegroundColor Yellow
    Write-Host "Adding $goBinPath to user PATH..." -ForegroundColor Cyan
    
    # Add to user PATH
    $newUserPath = "$userPath;$goBinPath"
    [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
    
    Write-Host "✅ Added $goBinPath to user PATH" -ForegroundColor Green
    Write-Host "Note: You may need to restart your terminal/PowerShell for changes to take effect" -ForegroundColor Yellow
}

# Test if tools are now accessible
Write-Host "`n🧪 Testing tool recognition..." -ForegroundColor Cyan

# Temporarily add to current session PATH for testing
$env:PATH += ";$goBinPath"

# Test a few key tools
$tools = @("amass", "httpx", "gau", "waybackurls", "nuclei")
$allWorking = $true

foreach ($tool in $tools) {
    try {
        $result = & $tool -h 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $tool" -ForegroundColor Green
        } else {
            Write-Host "❌ $tool" -ForegroundColor Red
            $allWorking = $false
        }
    } catch {
        Write-Host "❌ $tool" -ForegroundColor Red
        $allWorking = $false
    }
}

Write-Host "`n" + "=" * 50
if ($allWorking) {
    Write-Host "🎯 All Go tools are now accessible!" -ForegroundColor Green
    Write-Host "bughunter3.py should now recognize all required tools" -ForegroundColor Green
} else {
    Write-Host "⚠️ Some tools may still need to be installed" -ForegroundColor Yellow
    Write-Host "Run bughunter3.py and click 'Install/Update Tools'" -ForegroundColor Cyan
}

Write-Host "`n💡 To make changes permanent, restart your terminal or run:" -ForegroundColor Cyan
Write-Host "refreshenv" -ForegroundColor White 