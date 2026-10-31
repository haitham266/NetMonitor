; ملف التثبيت — مراقب الشبكة (Inno Setup 6)
#define AppName "مراقب الشبكة"
#define AppExe "NetMonitor.exe"
#define AppVer "1.0"

[Setup]
AppId={{6F1C2B7A-4E9D-4C3B-9A51-3D5E7F902A11}
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher=NetMonitor
DefaultDirName={localappdata}\Programs\NetMonitor
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=NetMonitor-Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "إنشاء اختصار على سطح المكتب"; GroupDescription: "اختصارات:"
Name: "autostart"; Description: "تشغيل المراقبة تلقائياً مع ويندوز (تنبيهات بالخلفية)"; GroupDescription: "خيارات:"; Flags: unchecked

[Files]
Source: "dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\icon.ico"
Name: "{group}\إلغاء تثبيت {#AppName}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Registry]
; التشغيل مع ويندوز (نفس المفتاح الذي يستخدمه خيار الإعدادات داخل البرنامج)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetMonitor"; ValueData: """{app}\{#AppExe}"" --background"; Tasks: autostart
; حذف التشغيل التلقائي عند إلغاء التثبيت
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "NetMonitor"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "تشغيل {#AppName} الآن"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "KillApp"

[Code]
// إيقاف البرنامج إن كان يعمل قبل التحديث/التثبيت
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
