$ErrorActionPreference = 'Stop'

function Run-Checked([scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $ProjectDir 'app'
$SdkDir = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$BuildToolsDir = Join-Path $SdkDir 'build-tools\35.0.0'
$AndroidJar = Join-Path $SdkDir 'platforms\android-35\android.jar'
$BuildDir = Join-Path $AppDir 'build\manual'
$OutDir = Join-Path $AppDir 'build\outputs\apk\debug'

if (!(Test-Path $AndroidJar)) { throw "android.jar not found: $AndroidJar" }
if (!(Test-Path (Join-Path $BuildToolsDir 'aapt2.exe'))) { throw "Android build tools 35.0.0 not found: $BuildToolsDir" }

Remove-Item -Recurse -Force $BuildDir, $OutDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $BuildDir, $OutDir | Out-Null
$CompileAndroidJar = Join-Path $BuildDir 'android.jar'
Copy-Item -Force $AndroidJar $CompileAndroidJar

$ResZip = Join-Path $BuildDir 'resources.zip'
$LinkedApk = Join-Path $BuildDir 'resources.apk'
$ManifestIn = Join-Path $AppDir 'src\main\AndroidManifest.xml'
$ManifestTmp = Join-Path $BuildDir 'AndroidManifest.xml'
$ManifestText = Get-Content -Raw $ManifestIn
if ($ManifestText -notmatch '<manifest[^>]*\spackage=') {
    $ManifestText = $ManifestText -replace '<manifest ', '<manifest package="com.codex.ajieandroid" '
}
[IO.File]::WriteAllText($ManifestTmp, $ManifestText, [Text.UTF8Encoding]::new($false))

Run-Checked { & (Join-Path $BuildToolsDir 'aapt2.exe') compile --dir (Join-Path $AppDir 'src\main\res') -o $ResZip }
Run-Checked { & (Join-Path $BuildToolsDir 'aapt2.exe') link -I $AndroidJar --manifest $ManifestTmp --java (Join-Path $BuildDir 'gen') --min-sdk-version 23 --target-sdk-version 35 --version-code 1 --version-name 1.0.0 --debug-mode -o $LinkedApk $ResZip }

$ClassesDir = Join-Path $BuildDir 'classes'
New-Item -ItemType Directory -Force -Path $ClassesDir | Out-Null
$JavaFiles = @()
$JavaFiles += Get-ChildItem -Recurse -Filter *.java (Join-Path $AppDir 'src\main\java') | ForEach-Object FullName
$JavaFiles += Get-ChildItem -Recurse -Filter *.java (Join-Path $BuildDir 'gen') | ForEach-Object FullName

if (Test-Path 'C:\Program Files\Microsoft\jdk-17.0.16.8-hotspot') {
    $env:JAVA_HOME = 'C:\Program Files\Microsoft\jdk-17.0.16.8-hotspot'
    $env:Path = "$env:JAVA_HOME\bin;$env:Path"
}
Run-Checked { & javac -encoding UTF-8 -source 8 -target 8 -classpath $CompileAndroidJar -d $ClassesDir $JavaFiles }

$DexOut = Join-Path $BuildDir 'dex'
New-Item -ItemType Directory -Force -Path $DexOut | Out-Null
$ClassFiles = Get-ChildItem -Recurse -Filter *.class $ClassesDir | ForEach-Object FullName
Run-Checked { & (Join-Path $BuildToolsDir 'd8.bat') --lib $CompileAndroidJar --output $DexOut $ClassFiles }
if (!(Test-Path (Join-Path $DexOut 'classes.dex'))) { throw 'classes.dex not generated' }

$UnsignedApk = Join-Path $BuildDir 'app-debug-unsigned.apk'
Copy-Item $LinkedApk $UnsignedApk
Push-Location $DexOut
try {
    Run-Checked { & jar uf $UnsignedApk classes.dex }
} finally {
    Pop-Location
}

$AlignedApk = Join-Path $BuildDir 'app-debug-aligned.apk'
Run-Checked { & (Join-Path $BuildToolsDir 'zipalign.exe') -p -f 4 $UnsignedApk $AlignedApk }

$KeyStore = Join-Path $BuildDir 'debug.keystore'
Run-Checked { & keytool -genkeypair -keystore $KeyStore -storepass android -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname 'CN=Android Debug,O=Android,C=US' }

$SignedApk = Join-Path $OutDir 'app-debug.apk'
Run-Checked { & (Join-Path $BuildToolsDir 'apksigner.bat') sign --ks $KeyStore --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out $SignedApk $AlignedApk }
Run-Checked { & (Join-Path $BuildToolsDir 'apksigner.bat') verify --verbose $SignedApk }

$ReleaseCopy = Join-Path $ProjectDir 'app-debug.apk'
Copy-Item -Force $SignedApk $ReleaseCopy
Get-Item $SignedApk, $ReleaseCopy | Select-Object FullName, Length, LastWriteTime
