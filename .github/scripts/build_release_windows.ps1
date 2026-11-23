# Use the same developer environment to record tool versions and compile both executables.
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$installation = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json |
    ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1) {
    throw 'Could not select the Visual Studio installation for the release'
}
$developerShell = Join-Path $installation.installationPath 'Common7/Tools/Launch-VsDevShell.ps1'
& $developerShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation

$bin = Join-Path $env:VCToolsInstallDir 'bin/Hostx64/x64'
function Get-MsvcToolVersion($name) {
    $tool = Get-Command $name -CommandType Application | Select-Object -First 1
    $expected = Get-Item -LiteralPath (Join-Path $bin $name)
    if ($tool.Source -ne $expected.FullName) { throw "Wrong MSVC executable selected for $name" }
    return $expected.VersionInfo.FileVersionRaw.ToString()
}

$env:IRMIND_VISUAL_STUDIO_VERSION = $installation.installationVersion
$env:IRMIND_CL_VERSION = Get-MsvcToolVersion 'cl.exe'
$env:IRMIND_LINK_VERSION = Get-MsvcToolVersion 'link.exe'

if ($env:OBSERVE_NATIVE_MAPPING_INPUTS -eq 'true') {
    python .github/scripts/build_release_binaries.py $env:DESTINATION mapping-input --observe-only
    exit $LASTEXITCODE
}

$buildOptions = @('--mapping-inputs', 'mapping-inputs/NATIVE-MAPPING-INPUTS.json')
if ($env:COMPARE_WINDOWS_MAPPINGS -eq 'true') { $buildOptions += '--compare-windows-mappings' }
python .github/scripts/build_release_binaries.py $env:DESTINATION dist --verify @buildOptions
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python .github/scripts/release_build_environment.py record $env:DESTINATION $env:RUNNER_LABEL dist/BUILD-ENVIRONMENT.json
exit $LASTEXITCODE
