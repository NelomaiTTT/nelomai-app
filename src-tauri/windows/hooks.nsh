!macro NSIS_HOOK_PREINSTALL
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  IfFileExists "$INSTDIR\nelomai-windows-service.exe" 0 nelomai_preinstall_done
    DetailPrint "Stopping the previous Nelomai tunnel service"
    ExecWait '"$INSTDIR\nelomai-windows-service.exe" uninstall' $0
    ${If} $0 <> 0
      MessageBox MB_ICONSTOP "Не удалось остановить предыдущую службу подключения Nelomai."
      Abort
    ${EndIf}
  nelomai_preinstall_done:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Installing the Nelomai tunnel service"
  nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -Command "$name=(Get-CimInstance Win32_ComputerSystem).UserName; if(-not $name){exit 1}; [Console]::Write((New-Object System.Security.Principal.NTAccount($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value)"'
  Pop $0
  Pop $1
  ${If} $0 <> 0
    MessageBox MB_ICONSTOP "Не удалось определить пользователя для службы подключения Nelomai."
    Abort
  ${EndIf}

  ExecWait '"$INSTDIR\nelomai-windows-service.exe" install --owner-sid "$1" --client-path "$INSTDIR\${MAINBINARYNAME}.exe"' $0
  ${If} $0 <> 0
    MessageBox MB_ICONSTOP "Не удалось установить службу подключения Nelomai."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  IfFileExists "$INSTDIR\nelomai-windows-service.exe" 0 nelomai_preuninstall_done
    DetailPrint "Removing the Nelomai tunnel service"
    ExecWait '"$INSTDIR\nelomai-windows-service.exe" uninstall' $0
    ${If} $0 <> 0
      MessageBox MB_ICONSTOP "Не удалось удалить службу подключения Nelomai."
      Abort
    ${EndIf}
  nelomai_preuninstall_done:
!macroend
