; ============================================================================
; 传书 (ChuanShu) PC 端 - Inno Setup 打包脚本
;
; 常规入口（不要直接跑 ISCC，改版本只需动 app/meta.py）：
;     powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task installer
; build.ps1 会从 app/meta.py 读取并通过 /D 传入下列四个宏：
;     AppName / AppVersion / Publisher / InnoDir（ISCC.exe 所在目录，用于探测自带语言）
; 下面的 #ifndef 默认值只是为了让你能单独用 ISCC.exe 直接编译本脚本做语法检查。
;
; 产物：dist\installer\{AppName}-Setup-{AppVersion}-x64.exe
; 前置：dist\{AppName}\ 必须已由 PyInstaller 生成（build.ps1 -Task exe），
;       否则 [Files] 段找不到源文件会直接报错。
; ============================================================================

#ifndef AppName
  #define AppName "ChuanShu"
#endif
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef Publisher
  #define Publisher "ChuanShu"
#endif
; 未经 build.ps1 调用时 InnoDir 为空，此时只探测项目内的语言文件。
#ifndef InnoDir
  #define InnoDir ""
#endif

#define AppExeName AppName + ".exe"
; PyInstaller one-folder 输出目录，整个目录（含 _internal）原样拷进 {app}。
#define DistDir "..\dist\" + AppName
; 简体中文消息文件的两级来源：项目内覆盖副本优先，其次编译器自带。
#define LocalZh AddBackslash(SourcePath) + "languages\ChineseSimplified.isl"
#define BundledZh AddBackslash(InnoDir) + "Languages\ChineseSimplified.isl"
; 免责声明文本，按安装向导语言各自取一份。
#define LicEn AddBackslash(SourcePath) + "licenses\disclaimer-en.txt"
#define LicZh AddBackslash(SourcePath) + "licenses\disclaimer-zh_CN.txt"

[Setup]
; ---- 基本信息：开始菜单、卸载列表、窗口标题都取自这几项 ----
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
AppSupportURL=https://example.com/support

; ---- 安装目录选择 ----
; {autopf} 会按实际权限解析：普通权限装到 %LOCALAPPDATA%\Programs，
; 管理员权限装到 Program Files。配合 PrivilegesRequiredOverridesAllowed=dialog，
; 用户在欢迎页选"为本机所有用户安装"后，同一份脚本就能装到 Program Files。
DefaultDirName={autopf}\{#AppName}
; 显式打开"选择安装位置"页（auto 在某些场景会跳过，这里不允许被跳过）。
DisableDirPage=no
; 在"准备安装"页再显示一次最终路径，方便用户装前回看。
AlwaysShowDirOnReadyPage=yes

; ---- 语言选择 ----
; 按界面语言（而非 ANSI 代码页）探测系统语言，中文系统直接进简体中文向导。
LanguageDetectionMethod=uilanguage
; yes = 向导第一屏始终给出语言下拉框；只有一个语言时想自动隐藏就改成 auto。
ShowLanguageDialog=yes

; ---- 快捷方式分组 ----
DefaultGroupName={#AppName}
; 只有应用本身一个入口，不需要"程序组"选择页，直接省掉。
DisableProgramGroupPage=yes

; ---- 输出与压缩 ----
OutputDir=..\dist\installer
OutputBaseFilename={#AppName}-Setup-{#AppVersion}-x64
; lzma2/max + solid：122MB 的 Qt one-folder 目录压到约 35MB。
Compression=lzma2/max
SolidCompression=yes

; ---- 外观与平台 ----
WizardStyle=modern
; 只允许 64 位 x64 机器安装；x64compatible 需要 Inno Setup >= 6.3。
ArchitecturesAllowed=x64compatible
; 让 {autopf}/{common*} 走 64 位视图，不被 WOW6432Node 重定向到 Program Files (x86)。
ArchitecturesInstallIn64BitMode=x64compatible

; ---- 权限与卸载 ----
; 默认按当前用户安装（免 UAC）；欢迎页的覆盖选项允许升级为全机器安装。
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
; 卸载列表里的图标用主程序自身，避免另存一个 .ico。
UninstallDisplayIcon={app}\{#AppExeName}

; ---- 免责声明 ----
; 文本挂在 [Languages] 的 LicenseFile 上（随向导语言切换）。Inno 的许可页默认就是
; 强制同意：只有选中"我接受"后"下一步"才可用，选"我拒绝"则无法继续，
; 因此不需要额外 [Code] 校验；若要加"必须勾选复选框"式的强确认才用 [Code] 钩子。

[Languages]
; Default.isl 就是英文，Inno 6/7 都有；Inno 7 删掉了 Languages\English.isl，
; 所以不要写死那条路径。列在第一个的语言是下拉框的默认选中顺序基准。
; LicenseFile 跟随语言条目：用户在下拉框切换向导语言，免责声明页文本一起换。
Name: "en"; MessagesFile: "compiler:Default.isl"; LicenseFile: "{#LicEn}"
; 简体中文三级回退：项目内 installer\languages\ChineseSimplified.isl（可自行修订术语）
;   -> 编译器自带（7.0 起官方内置；6.x 需 unofficial 语言包）
;   -> 都没有则安装包只提供英文，向导仍能正常工作。
#if FileExists(LocalZh)
Name: "zh_CN"; MessagesFile: "languages\ChineseSimplified.isl"; LicenseFile: "{#LicZh}"
#else
#if FileExists(BundledZh)
Name: "zh_CN"; MessagesFile: "{#BundledZh}"; LicenseFile: "{#LicZh}"
#endif
#endif

[Tasks]
; {cm:xxx} 引用的是当前 .isl 里的消息键，换语言文件时键名不能改。
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; 整棵 one-folder 树原样复制：ChuanShu.exe + _internal\（含 PySide6、locale\**.mo 与 assets\icons\）。
; 不要在这里做 flatten/rename，_internal 的相对结构是 PyInstaller 运行时依赖。
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; {group} = 开始菜单文件夹；{autodesktop} 随安装权限自动选当前用户或公共桌面。
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; 完成页的"运行"勾选项。& 要转义成 &&，否则会被当成助记符下划线。
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
