Var NelomaiOwnerSid
Var NelomaiOwnerProfile
Var NelomaiLegacyStartShortcut
Var NelomaiLegacyDesktopShortcut
Var NelomaiLegacyStartShortcutPath
Var NelomaiLegacyDesktopShortcutPath

!macro NSIS_HOOK_PREINSTALL
  StrCpy $NelomaiLegacyStartShortcut 0
  StrCpy $NelomaiLegacyDesktopShortcut 0
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -Command "$name=(Get-CimInstance Win32_ComputerSystem).UserName; if(-not $name){exit 1}; [Console]::Write((New-Object System.Security.Principal.NTAccount($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value)"'
  Pop $0
  Pop $NelomaiOwnerSid
  ${If} $0 <> 0
    MessageBox MB_ICONSTOP "Не удалось определить пользователя для установки Nelomai."
    Abort
  ${EndIf}

  ReadRegStr $NelomaiOwnerProfile HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$NelomaiOwnerSid" "ProfileImagePath"
  ExpandEnvStrings $NelomaiOwnerProfile "$NelomaiOwnerProfile"

  ; v0.1.0 used Tauri's current-user default. Before touching it, verify both
  ; its registry identity and exact default installation path.
  ReadRegStr $2 HKU "$NelomaiOwnerSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "DisplayName"
  StrCmp $2 "${PRODUCTNAME}" 0 nelomai_legacy_install_done
  ReadRegStr $2 HKU "$NelomaiOwnerSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "UninstallString"
  StrCmp $2 "$\"$NelomaiOwnerProfile\AppData\Local\Nelomai\uninstall.exe$\"" 0 nelomai_legacy_install_done
  IfFileExists "$NelomaiOwnerProfile\AppData\Local\Nelomai\uninstall.exe" 0 nelomai_legacy_install_done

    ; Preserve whether the user kept each legacy shortcut. The per-machine
    ; replacements are created only for shortcuts that actually existed.
    StrCpy $NelomaiLegacyStartShortcutPath "$NelomaiOwnerProfile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\${PRODUCTNAME}.lnk"
    !insertmacro IsShortcutTarget "$NelomaiLegacyStartShortcutPath" "$NelomaiOwnerProfile\AppData\Local\Nelomai\${MAINBINARYNAME}.exe"
    Pop $2
    ${If} $2 = 1
      StrCpy $NelomaiLegacyStartShortcut 1
    ${EndIf}

    ReadRegStr $NelomaiLegacyDesktopShortcutPath HKU "$NelomaiOwnerSid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" "Desktop"
    ${If} $NelomaiLegacyDesktopShortcutPath == ""
      StrCpy $NelomaiLegacyDesktopShortcutPath "$NelomaiOwnerProfile\Desktop"
    ${EndIf}
    !insertmacro IsShortcutTarget "$NelomaiLegacyDesktopShortcutPath\${PRODUCTNAME}.lnk" "$NelomaiOwnerProfile\AppData\Local\Nelomai\${MAINBINARYNAME}.exe"
    Pop $2
    ${If} $2 = 1
      StrCpy $NelomaiLegacyDesktopShortcut 1
    ${EndIf}

    ; /UPDATE preserves app data, autostart and shortcuts. We remove only the
    ; exact verified legacy shortcuts ourselves after the uninstaller finishes.
    DetailPrint "Removing the legacy per-user Nelomai installation"
    nsis_tauri_utils::RunAsUser "$NelomaiOwnerProfile\AppData\Local\Nelomai\uninstall.exe" "/S /UPDATE"
    Pop $2
    ${If} $2 <> 0
      MessageBox MB_ICONSTOP "Не удалось запустить удаление старой установки Nelomai."
      Abort
    ${EndIf}

    StrCpy $2 0
    nelomai_legacy_install_wait:
      Sleep 250
      ReadRegStr $3 HKU "$NelomaiOwnerSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "UninstallString"
      IfFileExists "$NelomaiOwnerProfile\AppData\Local\Nelomai\uninstall.exe" nelomai_legacy_install_wait_again 0
      StrCmp $3 "" nelomai_legacy_install_finished nelomai_legacy_install_wait_again
    nelomai_legacy_install_wait_again:
      IntOp $2 $2 + 1
      ${If} $2 >= 480
        MessageBox MB_ICONSTOP "Удаление старой установки Nelomai не завершилось вовремя."
        Abort
      ${EndIf}
      Goto nelomai_legacy_install_wait
    nelomai_legacy_install_finished:
      ${If} $NelomaiLegacyStartShortcut = 1
        !insertmacro UnpinShortcut "$NelomaiLegacyStartShortcutPath"
        Delete "$NelomaiLegacyStartShortcutPath"
      ${EndIf}
      ${If} $NelomaiLegacyDesktopShortcut = 1
        Delete "$NelomaiLegacyDesktopShortcutPath\${PRODUCTNAME}.lnk"
      ${EndIf}
  nelomai_legacy_install_done:

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
  ExecWait '"$INSTDIR\nelomai-windows-service.exe" install --owner-sid "$NelomaiOwnerSid" --client-path "$INSTDIR\${MAINBINARYNAME}.exe"' $0
  ${If} $0 <> 0
    MessageBox MB_ICONSTOP "Не удалось установить службу подключения Nelomai."
    Abort
  ${EndIf}

  ; Tauri keeps the original Start menu shortcut during /UPDATE. Refresh
  ; existing shortcuts so Windows Search picks up the current executable icon.
  ; A verified legacy shortcut is replaced even if no per-machine shortcut exists.
  ${If} $UpdateMode = 1
    !insertmacro MUI_STARTMENU_GETFOLDER Application $AppStartMenuFolder
    !if "${STARTMENUFOLDER}" != ""
      IfFileExists "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" nelomai_refresh_start_menu_shortcut 0
      StrCmp $NelomaiLegacyStartShortcut 1 nelomai_refresh_start_menu_shortcut nelomai_start_menu_shortcut_done
      nelomai_refresh_start_menu_shortcut:
        CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
        Delete "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
        CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
        !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
    !else
      IfFileExists "$SMPROGRAMS\${PRODUCTNAME}.lnk" nelomai_refresh_start_menu_shortcut 0
      StrCmp $NelomaiLegacyStartShortcut 1 nelomai_refresh_start_menu_shortcut nelomai_start_menu_shortcut_done
      nelomai_refresh_start_menu_shortcut:
        Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
        CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
        !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    !endif
    nelomai_start_menu_shortcut_done:

    IfFileExists "$DESKTOP\${PRODUCTNAME}.lnk" nelomai_refresh_desktop_shortcut 0
    StrCmp $NelomaiLegacyDesktopShortcut 1 nelomai_refresh_desktop_shortcut nelomai_desktop_shortcut_done
    nelomai_refresh_desktop_shortcut:
      Delete "$DESKTOP\${PRODUCTNAME}.lnk"
      CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
      !insertmacro SetLnkAppUserModelId "$DESKTOP\${PRODUCTNAME}.lnk"
    nelomai_desktop_shortcut_done:
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
