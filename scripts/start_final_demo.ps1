param(
    [ValidateSet('Replay', 'Live-Normal', 'Live-PreBlock', 'Live-Injection')]
    [string]$Mode = 'Replay',
    [ValidateSet('A', 'B', 'C', 'D')]
    [string]$Condition = 'C',
    [int]$Port = 8501
)
$ErrorActionPreference = 'Stop'
$demoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $demoRoot
try {
    & uv sync --locked --group dev --group demo
    if ($LASTEXITCODE -ne 0) { throw 'Dependency sync failed' }
    if ($Mode -eq 'Replay') {
        & uv run streamlit run demo/final_dashboard.py --server.address 127.0.0.1 --server.port $Port --server.headless true --browser.gatherUsageStats false
    } else {
        if (-not $env:LLM_BASE_URL) { $env:LLM_BASE_URL = 'http://127.0.0.1:11434/v1' }
        if (-not $env:LLM_MODEL) { $env:LLM_MODEL = 'qwen3:8b' }
        if (-not $env:LLM_MAX_TOKENS) { $env:LLM_MAX_TOKENS = '2048' }
        if (-not $env:LLM_TIMEOUT_SEC) { $env:LLM_TIMEOUT_SEC = '600' }
        $demoPrivate = Join-Path $env:LOCALAPPDATA ('GuardOn\demo\' + [guid]::NewGuid().ToString())
        $scenario = @{'Live-Normal'='normal'; 'Live-PreBlock'='unauthorized-email'; 'Live-Injection'='indirect-injection'}[$Mode]
        Write-Output "Private evidence output: $demoPrivate"
        & uv run python examples/run_agent_mcp_e2e.py --condition $Condition --pit01 --scenario $scenario --output-dir $demoPrivate
    }
    if ($LASTEXITCODE -ne 0) { throw "Demo exited with status $LASTEXITCODE" }
} finally {
    Pop-Location
}
