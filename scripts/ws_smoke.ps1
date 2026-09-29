#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    WebSocket smoke test for forge-server /ws/progress endpoint.

.DESCRIPTION
    Connects to ws://HOST:PORT/ws/progress, sends "ping", expects "ping" echo back.
    Exits 0 on success, 1 on failure.

.PARAMETER Host
    Server hostname (default: localhost)

.PARAMETER Port
    Server port (default: 9000)

.EXAMPLE
    pwsh scripts\ws_smoke.ps1
    pwsh scripts\ws_smoke.ps1 -Port 19000
    pwsh scripts\ws_smoke.ps1 -Host localhost -Port 9000
#>
param(
    [string]$ServerHost = "localhost",
    [int]$Port = 9000,
    [int]$TimeoutMs = 3000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$uri = [Uri]"ws://${ServerHost}:${Port}/ws/progress"
Write-Host "WS smoke: connecting to $uri ..."

$ws = [System.Net.WebSockets.ClientWebSocket]::new()
$cts = [System.Threading.CancellationTokenSource]::new($TimeoutMs)

try {
    # Connect
    $connectTask = $ws.ConnectAsync($uri, $cts.Token)
    if (-not $connectTask.Wait($TimeoutMs)) {
        Write-Error "FAIL: connect timed out after ${TimeoutMs}ms"
        exit 1
    }
    if ($connectTask.IsFaulted) {
        Write-Error "FAIL: connect error: $($connectTask.Exception.InnerException.Message)"
        exit 1
    }
    if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
        Write-Error "FAIL: WebSocket not open (state=$($ws.State))"
        exit 1
    }
    Write-Host "WS smoke: connected (state=$($ws.State))"

    # Send "ping"
    $sendMsg = "ping"
    $sendBytes = [System.Text.Encoding]::UTF8.GetBytes($sendMsg)
    $sendSeg  = [ArraySegment[byte]]::new($sendBytes)
    $sendTask = $ws.SendAsync($sendSeg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token)
    if (-not $sendTask.Wait($TimeoutMs)) {
        Write-Error "FAIL: send timed out"
        exit 1
    }
    Write-Host "WS smoke: sent '$sendMsg'"

    # Receive echo
    $recvBuf  = [byte[]]::new(4096)
    $recvSeg  = [ArraySegment[byte]]::new($recvBuf)
    $recvTask = $ws.ReceiveAsync($recvSeg, $cts.Token)
    if (-not $recvTask.Wait($TimeoutMs)) {
        Write-Error "FAIL: receive timed out after ${TimeoutMs}ms"
        exit 1
    }
    if ($recvTask.IsFaulted) {
        Write-Error "FAIL: receive error: $($recvTask.Exception.InnerException.Message)"
        exit 1
    }

    $result  = $recvTask.Result
    $recvMsg = [System.Text.Encoding]::UTF8.GetString($recvBuf, 0, $result.Count)
    Write-Host "WS smoke: received '$recvMsg'"

    if ($recvMsg -ne $sendMsg) {
        Write-Error "FAIL: expected '$sendMsg', got '$recvMsg'"
        exit 1
    }

    # Graceful close
    $closeTask = $ws.CloseAsync(
        [System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,
        "smoke-done",
        [System.Threading.CancellationToken]::None
    )
    $null = $closeTask.Wait(2000)  # ignore close-handshake errors — server may close first

    Write-Host "WS smoke: PASS (echo verified)"
    exit 0
}
catch {
    Write-Error "FAIL: $_"
    exit 1
}
finally {
    $ws.Dispose()
    $cts.Dispose()
}
