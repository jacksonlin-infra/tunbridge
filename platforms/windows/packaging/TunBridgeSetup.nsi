Unicode True
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef PRODUCT_VERSION
  !error "PRODUCT_VERSION is required"
!endif
!ifndef FILE_VERSION
  !error "FILE_VERSION is required"
!endif
!ifndef PACKAGE_DIR
  !error "PACKAGE_DIR is required"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif
!ifndef PRODUCT_ICON
  !error "PRODUCT_ICON is required"
!endif

!define PRODUCT_NAME "TunBridge"
!define PRODUCT_PUBLISHER "TunBridge Project"
!define PRODUCT_REGISTRY_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\TunBridge"
!define BOOTSTRAP_DIRECTORY "$PROGRAMFILES64\TunBridge Installer"
!define PRODUCT_DIRECTORY "$PROGRAMFILES64\TunBridge"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "${BOOTSTRAP_DIRECTORY}"
Icon "${PRODUCT_ICON}"
UninstallIcon "${PRODUCT_ICON}"
BrandingText "TunBridge Project"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=1033 "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=1033 "FileDescription" "TunBridge Setup"
VIAddVersionKey /LANG=1033 "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "GPL-3.0-or-later"

!define MUI_ABORTWARNING
!define MUI_ICON "${PRODUCT_ICON}"
!define MUI_UNICON "${PRODUCT_ICON}"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchTunBridgeAsUser
!define MUI_FINISHPAGE_RUN_TEXT "Start TunBridge"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "TunBridge requires 64-bit Windows."
    SetErrorLevel 1
    Quit
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function LaunchTunBridgeAsUser
  ; Setup is elevated. Explorer launches the Desktop in the interactive
  ; user's normal integrity context, matching later shortcut launches.
  ExecShell "open" "$WINDIR\explorer.exe" '"${PRODUCT_DIRECTORY}\tunbridge-desktop.exe"'
FunctionEnd

Section "TunBridge" SEC_PRODUCT
  SectionIn RO
  InitPluginsDir
  CreateDirectory "$PLUGINSDIR\TunBridgePackage"
  SetOutPath "$PLUGINSDIR\TunBridgePackage"
  File "/oname=tunbridge-desktop.exe" "${PACKAGE_DIR}\tunbridge-desktop.exe"
  File "/oname=tunbridge-setup.exe" "${PACKAGE_DIR}\tunbridge-setup.exe"
  File "/oname=tunbridge-service.exe" "${PACKAGE_DIR}\tunbridge-service.exe"
  File "/oname=tunbridge.exe" "${PACKAGE_DIR}\tunbridge.exe"
  File "/oname=mihomo.exe" "${PACKAGE_DIR}\mihomo.exe"
  File "/oname=engines.lock.json" "${PACKAGE_DIR}\engines.lock.json"
  File "/oname=product-package.json" "${PACKAGE_DIR}\product-package.json"

  DetailPrint "Installing or upgrading the verified TunBridge product generation..."
  ExecWait '"$PLUGINSDIR\TunBridgePackage\tunbridge-setup.exe" install' $0
  ${If} $0 != 0
    IfSilent +2
      MessageBox MB_ICONSTOP|MB_OK "TunBridge setup could not complete safely. The previous working version was preserved when available."
    SetErrorLevel $0
    Quit
  ${EndIf}

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\TunBridge"
  CreateShortcut "$SMPROGRAMS\TunBridge\TunBridge.lnk" "${PRODUCT_DIRECTORY}\tunbridge-desktop.exe"
  CreateShortcut "$SMPROGRAMS\TunBridge\Uninstall TunBridge.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\TunBridge.lnk" "${PRODUCT_DIRECTORY}\tunbridge-desktop.exe"

  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "DisplayName" "TunBridge"
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "DisplayIcon" "${PRODUCT_DIRECTORY}\tunbridge-desktop.exe"
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "InstallLocation" "${PRODUCT_DIRECTORY}"
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${PRODUCT_REGISTRY_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${PRODUCT_REGISTRY_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${PRODUCT_REGISTRY_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ${If} ${FileExists} "${PRODUCT_DIRECTORY}\tunbridge-setup.exe"
    DetailPrint "Stopping TunBridge and restoring the verified network state..."
    ExecWait '"${PRODUCT_DIRECTORY}\tunbridge-setup.exe" uninstall' $0
    ${If} $0 != 0
      IfSilent +2
        MessageBox MB_ICONSTOP|MB_OK "TunBridge could not be removed safely. Its service and network state were preserved for recovery."
      SetErrorLevel $0
      Quit
    ${EndIf}
  ${EndIf}

  Delete "$DESKTOP\TunBridge.lnk"
  Delete "$SMPROGRAMS\TunBridge\TunBridge.lnk"
  Delete "$SMPROGRAMS\TunBridge\Uninstall TunBridge.lnk"
  RMDir "$SMPROGRAMS\TunBridge"
  DeleteRegKey HKLM "${PRODUCT_REGISTRY_KEY}"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
