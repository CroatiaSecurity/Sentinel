# Rename all GitHub releases from X.Y.Z scheme to 0.X.Y scheme
# Run: gh auth login (first), then .\scripts\rename-github-releases.ps1

$env:PATH = "C:\Program Files\Git\bin;C:\Users\Admin\AppData\Local\Temp\gh\bin;$env:PATH"
$repo = "CroatiaSecurity/Sentinel"

# Map old tag -> new tag
$tagMap = @{
    "1.7.0" = "v0.1.7"; "1.8.0" = "v0.1.8"; "1.9.0" = "v0.1.9"
    "2.0.0" = "v0.2.0"; "2.1.0" = "v0.2.1"; "2.2.0" = "v0.2.2"
    "2.3.0" = "v0.2.3"; "2.4.0" = "v0.2.4"; "2.5.0" = "v0.2.5"
    "2.6.0" = "v0.2.6"; "2.7.0" = "v0.2.7"; "2.8.0" = "v0.2.8"; "2.8.1" = "v0.2.8.1"
    "3.0.0" = "v0.3.0"; "3.1.0" = "v0.3.1"; "3.2.0" = "v0.3.2"
    "3.3.0" = "v0.3.3"; "3.4.0" = "v0.3.4"; "3.5.0" = "v0.3.5"
    "3.6.0" = "v0.3.6"; "3.7.0" = "v0.3.7"; "3.8.0" = "v0.3.8"; "3.9.0" = "v0.3.9"
    "4.0.0" = "v0.4.0"; "4.1.0" = "v0.4.1"; "4.2.0" = "v0.4.2"
    "4.3.0" = "v0.4.3"; "4.4.0" = "v0.4.4"; "4.5.0" = "v0.4.5"
    "4.6.0" = "v0.4.6"; "4.7.0" = "v0.4.7"; "4.8.0" = "v0.4.8"; "4.8.1" = "v0.4.8.1"
    "5.0.0" = "v0.5.0"; "5.1.0" = "v0.5.1"
    "v5.3.0" = "v0.5.3"; "v5.4.0" = "v0.5.4"; "v5.5.0" = "v0.5.5"
    "v5.6.0" = "v0.5.6"; "v5.7.0" = "v0.5.7"; "v5.8.0" = "v0.5.8"
    "v5.9.0" = "v0.5.9"; "v5.9.1" = "v0.5.9.1"; "v5.9.2" = "v0.5.9.2"
    "v6.0.0" = "v0.6.0"; "v6.1.0" = "v0.6.1"; "v6.2.0" = "v0.6.2"
    "v6.3.0" = "v0.6.3"; "v6.8.0" = "v0.6.8"; "v6.9.0" = "v0.6.9"
}

foreach ($oldTag in $tagMap.Keys) {
    $newTag = $tagMap[$oldTag]
    
    # Extract version numbers for exe renaming
    $oldVer = $oldTag -replace '^v', ''
    $newVer = $newTag -replace '^v', ''
    
    Write-Host "Processing: $oldTag -> $newTag" -ForegroundColor Cyan
    
    # 1. Get the commit SHA for the old tag
    $sha = git rev-list -n 1 $oldTag 2>$null
    if (-not $sha) {
        Write-Host "  Tag $oldTag not found locally, skipping" -ForegroundColor Yellow
        continue
    }
    
    # 2. Edit the release title (rename it)
    $newTitle = "Windows Sentinel $newVer"
    gh release edit $oldTag --repo $repo --title $newTitle 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  No release for $oldTag or edit failed, skipping" -ForegroundColor Yellow
        continue
    }
    Write-Host "  Renamed release title to: $newTitle" -ForegroundColor Green
    
    # 3. Download, rename, and re-upload the exe asset
    $oldExeName = "WindowsSentinelSetup-$oldVer.exe"
    $altExeName = "Sentinel_$oldVer.exe"
    $newExeName = "Sentinel_$newVer.exe"
    
    # Try to download the asset
    $tempDir = "$env:TEMP\gh_rename_$oldVer"
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    $downloaded = $false
    foreach ($name in @($oldExeName, $altExeName)) {
        gh release download $oldTag --repo $repo --pattern $name --dir $tempDir 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path "$tempDir\$name")) {
            # Rename
            Rename-Item "$tempDir\$name" $newExeName
            # Delete old asset and upload renamed one
            gh release delete-asset $oldTag $name --repo $repo --yes 2>$null
            gh release upload $oldTag "$tempDir\$newExeName" --repo $repo 2>$null
            Write-Host "  Renamed asset: $name -> $newExeName" -ForegroundColor Green
            $downloaded = $true
            break
        }
    }
    
    if (-not $downloaded) {
        Write-Host "  No exe asset found to rename" -ForegroundColor Yellow
    }
    
    # 4. Rename the tag itself (delete old, create new at same commit)
    git tag $newTag $sha 2>$null
    git tag -d $oldTag 2>$null
    git push origin :refs/tags/$oldTag 2>$null
    git push origin $newTag 2>$null
    Write-Host "  Tag renamed: $oldTag -> $newTag" -ForegroundColor Green
    
    # Cleanup
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Milliseconds 500  # Rate limit
}

Write-Host ""
Write-Host "Done! All releases renamed." -ForegroundColor Green
Write-Host "Now commit and push the v0.7.0 release:" -ForegroundColor Yellow
Write-Host '  git add -A && git commit -m "Release v0.7.0: audit fixes, stub implementations, version scheme change"'
Write-Host '  git tag v0.7.0'
Write-Host '  git push origin main --tags'
Write-Host '  gh release create v0.7.0 --title "Windows Sentinel 0.7.0" --notes-file CHANGELOG_EXCERPT.md'
