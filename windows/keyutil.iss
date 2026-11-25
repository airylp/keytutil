; Instalador de keyutil para Windows (Inno Setup 6).
; Lo compila .github/workflows/release.yml:  iscc /DAppVersion=0.2.0 windows\keyutil.iss
; Necesita target\release\keyutil.exe ya compilado.
;
; Se instala para el usuario (sin pedir permisos de administrador), en
; %LOCALAPPDATA%\Programs\keyutil.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; Identificador fijo: con él Windows reconoce las actualizaciones y el desinstalador.
AppId={{8E1D848F-20F1-493A-A2D7-076EFB145F42}
AppName=keyutil
AppVersion={#AppVersion}
AppVerName=keyutil {#AppVersion}
AppPublisher=airylp
AppPublisherURL=https://github.com/airylp/keyutil
AppSupportURL=https://github.com/airylp/keyutil/issues
AppUpdatesURL=https://github.com/airylp/keyutil/releases
DefaultDirName={autopf}\keyutil
DefaultGroupName=keyutil
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\target\instalador
OutputBaseFilename=keyutil-{#AppVersion}-setup
SetupIconFile=keyutil.ico
UninstallDisplayIcon={app}\keyutil.exe
UninstallDisplayName=keyutil
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Si keyutil está abierto, el instalador ofrece cerrarlo (Restart Manager).
CloseApplications=yes
RestartApplications=no
ShowLanguageDialog=auto

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\target\release\keyutil.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
; OpenGL por software (Mesa llvmpipe) para equipos sin tarjeta gráfica utilizable.
Source: "..\target\release\opengl32.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\libgallium_wgl.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "MESA.txt"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Hasta la 0.1.3 la app se llamaba «keytutil».
Type: files; Name: "{app}\keytutil.exe"
Type: files; Name: "{autoprograms}\keytutil.lnk"
Type: files; Name: "{autodesktop}\keytutil.lnk"

[Icons]
Name: "{autoprograms}\keyutil"; Filename: "{app}\keyutil.exe"
Name: "{autodesktop}\keyutil"; Filename: "{app}\keyutil.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\keyutil.exe"; Description: "{cm:LaunchProgram,keyutil}"; Flags: nowait postinstall skipifsilent

[Code]
// Guarda el idioma elegido en el instalador como idioma de la app (si aún no
// hay uno elegido), igual que install.sh en macOS/Linux: `idioma = "xx"` al
// principio de sesion.toml.
procedure CurStepChanged(CurStep: TSetupStep);
var
  Dir, F, Rest: String;
  Lines: TArrayOfString;
  I: Integer;
  Has: Boolean;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Dir := ExpandConstant('{userappdata}\keyutil');
  F := Dir + '\sesion.toml';
  Has := False;
  Rest := '';
  if LoadStringsFromFile(F, Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
    begin
      if Pos('idioma', Trim(Lines[I])) = 1 then
        Has := True;
      Rest := Rest + Lines[I] + #13#10;
    end;
  if not Has then
  begin
    ForceDirectories(Dir);
    SaveStringToFile(F, 'idioma = "' + ActiveLanguage + '"' + #13#10 + Rest, False);
  end;
end;
