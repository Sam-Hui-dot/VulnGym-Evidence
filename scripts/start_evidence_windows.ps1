param(
    [ValidateSet('menu', 'deterministic', 'qwen', 'check')][string]$Mode = 'menu',
    [ValidateRange(1024, 65535)][int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$taskRepoPath = Split-Path -Parent $PSScriptRoot
$taskMode = @{ menu='menu'; deterministic='demo'; qwen='qwen'; check='check' }[$Mode]
if ($taskRepoPath -match '^\\\\(?:wsl\.localhost|wsl\$)\\([^\\]+)\\(.+)$') {
    $taskDistro = $Matches[1]
    $taskLinuxPath = '/' + $Matches[2].Replace('\', '/')
    & wsl.exe --distribution $taskDistro --cd $taskLinuxPath -- python3 scripts/start_desktop.py --mode $taskMode --port $Port
} else {
    $taskPython = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($taskPython) {
        & $taskPython.Source (Join-Path $taskRepoPath 'scripts\start_desktop.py') --mode $taskMode --port $Port
    } else {
        $taskPy = Get-Command py.exe -ErrorAction SilentlyContinue
        if (-not $taskPy) { throw 'Python 3.10+ is required. Install Python, then reopen this launcher.' }
        & $taskPy.Source -3 (Join-Path $taskRepoPath 'scripts\start_desktop.py') --mode $taskMode --port $Port
    }
}
if ($LASTEXITCODE -ne 0) { throw '启动未完成，请查看上方具体提示。' }
