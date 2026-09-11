#requires -RunAsAdministrator

<#
.SYNOPSIS
    Ferramenta interativa de segurança, auditoria e manutenção do Windows.

.DESCRIPTION
    Executa verificações do Microsoft Defender, atualiza definições,
    consulta ameaças detectadas, limpa arquivos temporários com confirmação
    e exibe conexões de rede ativas para auditoria rápida.

    Execute este script em um console do PowerShell aberto como Administrador.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$script:Title = 'Windows Security & Maintenance Tool'

function Write-Section {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Pause-Menu {
    [void](Read-Host "`nPressione ENTER para voltar ao menu")
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-DefenderCmdlet {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Warning "O cmdlet '$Name' não está disponível neste sistema."
        return $false
    }

    return $true
}

function Invoke-DefenderScan {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('QuickScan', 'FullScan')]
        [string]$ScanType
    )

    Write-Section "Microsoft Defender - $ScanType"

    if (-not (Test-DefenderCmdlet -Name 'Start-MpScan')) {
        Pause-Menu
        return
    }

    Write-Host "A varredura será iniciada. O tempo depende do volume de dados." `
        -ForegroundColor Yellow

    try {
        Start-MpScan -ScanType $ScanType -ErrorAction Stop
        Write-Host "Comando de varredura enviado com sucesso." `
            -ForegroundColor Green
    }
    catch {
        Write-Error "Não foi possível iniciar a varredura: $($_.Exception.Message)"
    }

    Pause-Menu
}

function Update-DefenderSignatures {
    Write-Section 'Atualização das definições do Defender'

    if (-not (Test-DefenderCmdlet -Name 'Update-MpSignature')) {
        Pause-Menu
        return
    }

    try {
        Update-MpSignature -ErrorAction Stop
        Write-Host "Definições atualizadas ou já estão na versão mais recente." `
            -ForegroundColor Green
    }
    catch {
        Write-Error "Falha ao atualizar as definições: $($_.Exception.Message)"
    }

    Pause-Menu
}

function Show-ThreatAudit {
    Write-Section 'Ameaças detectadas e itens em quarentena'

    if (-not (Test-DefenderCmdlet -Name 'Get-MpThreatDetection')) {
        Pause-Menu
        return
    }

    try {
        $threats = @(Get-MpThreatDetection -ErrorAction Stop)

        if ($threats.Count -eq 0) {
            Write-Host 'Nenhuma detecção foi retornada pelo Microsoft Defender.' `
                -ForegroundColor Green
        }
        else {
            $threats |
                Select-Object -Property DetectionTime, ThreatID, DomainUser,
                    ActionSuccess, Resources |
                Format-Table -AutoSize -Wrap

            Write-Host "`nTotal de registros: $($threats.Count)" `
                -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Falha ao consultar as detecções: $($_.Exception.Message)"
    }

    Pause-Menu
}

function Add-CleanupPath {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Paths,
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    try {
        $resolved = [Environment]::ExpandEnvironmentVariables($Path)
        if ((Test-Path -LiteralPath $resolved) -and
            -not $Paths.Contains($resolved)) {
            [void]$Paths.Add($resolved)
        }
    }
    catch {
        Write-Verbose "Caminho ignorado: $Path"
    }
}

function Get-CleanupPaths {
    $paths = [System.Collections.Generic.List[string]]::new()

    Add-CleanupPath -Paths $paths -Path $env:TEMP
    Add-CleanupPath -Paths $paths -Path $env:TMP
    Add-CleanupPath -Paths $paths -Path "$env:WINDIR\Temp"
    Add-CleanupPath -Paths $paths -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    Add-CleanupPath -Paths $paths -Path "$env:LOCALAPPDATA\D3DSCache"

    return $paths
}

function Remove-ContentsSafely {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $removed = 0
    $failed = 0

    try {
        $items = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
        foreach ($item in $items) {
            try {
                Remove-Item -LiteralPath $item.FullName -Recurse -Force `
                    -ErrorAction Stop
                $removed++
            }
            catch {
                $failed++
                Write-Verbose "Não foi possível remover $($item.FullName)"
            }
        }
    }
    catch {
        Write-Verbose "Não foi possível acessar $Path"
    }

    [PSCustomObject]@{
        Caminho = $Path
        Removidos = $removed
        Ignorados = $failed
    }
}

function Clear-SystemTemporaryData {
    Write-Section 'Limpeza segura de temporários e cache'
    Write-Host 'A limpeza remove apenas o conteúdo dos diretórios temporários' `
        -ForegroundColor Yellow
    Write-Host 'e do cache selecionado. Arquivos em uso serão preservados.' `
        -ForegroundColor Yellow

    $confirmation = Read-Host `
        'Digite LIMPAR para confirmar ou qualquer outra coisa para cancelar'
    if ($confirmation -cne 'LIMPAR') {
        Write-Host 'Operação cancelada; nenhum arquivo foi removido.' `
            -ForegroundColor DarkYellow
        Pause-Menu
        return
    }

    $paths = Get-CleanupPaths
    $results = foreach ($path in $paths) {
        Remove-ContentsSafely -Path $path
    }

    if (Get-Command -Name Clear-RecycleBin -ErrorAction SilentlyContinue) {
        $driveLetters = @($env:SystemDrive.TrimEnd(':'))
        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            $driveLetters = @(Get-CimInstance -ClassName Win32_LogicalDisk `
                    -Filter 'DriveType = 3' -ErrorAction SilentlyContinue |
                ForEach-Object { $_.DeviceID.TrimEnd(':') })
        }

        foreach ($drive in ($driveLetters | Sort-Object -Unique)) {
            try {
                Clear-RecycleBin -DriveLetter $drive -Force -ErrorAction Stop
                Write-Host "Lixeira da unidade $drive`: esvaziada." `
                    -ForegroundColor Green
            }
            catch {
                Write-Warning "A lixeira da unidade $drive`: não pôde ser esvaziada ou já estava vazia."
            }
        }
    }

    $results | Format-Table -AutoSize
    Write-Host 'Limpeza concluída. Arquivos bloqueados foram ignorados.' `
        -ForegroundColor Green
    Pause-Menu
}

function Get-ProcessName {
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId
    )

    try {
        return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    }
    catch {
        return 'N/D'
    }
}

function Show-NetworkAudit {
    Write-Section 'Auditoria de conexões e portas'

    if (-not (Get-Command -Name Get-NetTCPConnection `
            -ErrorAction SilentlyContinue)) {
        Write-Warning 'Get-NetTCPConnection não está disponível neste sistema.'
        Pause-Menu
        return
    }

    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Protocolo = 'TCP'
                Estado = $_.State
                EnderecoLocal = "$($_.LocalAddress):$($_.LocalPort)"
                EnderecoRemoto = "$($_.RemoteAddress):$($_.RemotePort)"
                PID = $_.OwningProcess
                Processo = Get-ProcessName -ProcessId $_.OwningProcess
            }
        })

        $udp = @()
        if (Get-Command -Name Get-NetUDPEndpoint `
            -ErrorAction SilentlyContinue) {
            $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [PSCustomObject]@{
                        Protocolo = 'UDP'
                        Estado = 'LISTENING'
                        EnderecoLocal = "$($_.LocalAddress):$($_.LocalPort)"
                        EnderecoRemoto = '-'
                        PID = $_.OwningProcess
                        Processo = Get-ProcessName -ProcessId $_.OwningProcess
                    }
                })
        }

        $connections = @($tcp + $udp) |
            Sort-Object Protocolo, Estado, EnderecoLocal

        if ($connections.Count -eq 0) {
            Write-Host 'Nenhuma conexão ou porta foi encontrada.' `
                -ForegroundColor Yellow
        }
        else {
            $connections | Format-Table -AutoSize -Wrap
            Write-Host "Total de entradas: $($connections.Count)" `
                -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Falha na auditoria de rede: $($_.Exception.Message)"
    }

    Pause-Menu
}

function Show-Menu {
    Clear-Host
    Write-Host "==============================================" `
        -ForegroundColor DarkCyan
    Write-Host " $script:Title" -ForegroundColor Cyan
    Write-Host "==============================================" `
        -ForegroundColor DarkCyan
    Write-Host 'Execute somente ações compatíveis com sua política de segurança.'
    Write-Host ''
    Write-Host '1. Executar QuickScan do Microsoft Defender'
    Write-Host '2. Executar FullScan do Microsoft Defender'
    Write-Host '3. Atualizar definições de vírus'
    Write-Host '4. Auditar ameaças e quarentena'
    Write-Host '5. Limpar temporários, cache e lixeira'
    Write-Host '6. Auditar conexões e portas de rede'
    Write-Host '0. Sair'
    Write-Host ''
}

if (-not (Test-Administrator)) {
    Write-Error 'Este script precisa ser executado como Administrador.'
    Write-Host 'Abra o PowerShell usando "Executar como administrador" e tente novamente.'
    exit 1
}

do {
    Show-Menu
    $option = Read-Host 'Escolha uma opção'

    switch ($option) {
        '1' { Invoke-DefenderScan -ScanType 'QuickScan' }
        '2' { Invoke-DefenderScan -ScanType 'FullScan' }
        '3' { Update-DefenderSignatures }
        '4' { Show-ThreatAudit }
        '5' { Clear-SystemTemporaryData }
        '6' { Show-NetworkAudit }
        '0' { Write-Host 'Encerrando a ferramenta.' -ForegroundColor Cyan }
        default {
            Write-Warning 'Opção inválida.'
            Start-Sleep -Seconds 1
        }
    }
} while ($option -ne '0')