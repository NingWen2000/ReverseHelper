param(
    [string]$Python = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistRoot = Join-Path $ProjectRoot "dist"
$WorkRoot = Join-Path $ProjectRoot "build\portable"
$PackageRoot = Join-Path $DistRoot "ReverseHelper-0.2.0b2-win-x64"

& $Python -m PyInstaller --noconfirm --onefile --console `
    --name ReverseHelper `
    --distpath $PackageRoot `
    --workpath $WorkRoot `
    --specpath $WorkRoot `
    (Join-Path $ProjectRoot "main.py")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

Copy-Item -LiteralPath (Join-Path $ProjectRoot "QUICKSTART.md") -Destination $PackageRoot
Copy-Item -LiteralPath (Join-Path $ProjectRoot "QUICKSTART.zh-CN.md") -Destination $PackageRoot
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.zh-CN.md") -Destination $PackageRoot
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") -Destination $PackageRoot
Copy-Item -LiteralPath (Join-Path $ProjectRoot "docs") -Destination $PackageRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "LICENSE") -Destination $PackageRoot
Copy-Item -LiteralPath (Join-Path $ProjectRoot "scripts\ImportReverseHelperFindings.py") -Destination $PackageRoot

$Archive = Join-Path $DistRoot "ReverseHelper-0.2.0b2-win-x64.zip"
Compress-Archive -Path (Join-Path $PackageRoot "*") -DestinationPath $Archive -Force
Write-Output $Archive
