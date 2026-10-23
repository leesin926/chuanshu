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
; 命令行是独立第二个 exe（app.spec 的 name=APP_NAME + "-cli"）。防火墙规则按程序路径判定，
; 所以 {#AppExeName} 放行了不代表这个放行了——两条路径各自都要写一遍。
#define AppCliExeName AppName + "-cli.exe"
; PyInstaller one-folder 输出目录，整个目录（含 _internal）原样拷进 {app}。
#define DistDir "..\dist\" + AppName
; 简体中文消息文件的两级来源：项目内覆盖副本优先，其次编译器自带。
#define LocalZh AddBackslash(SourcePath) + "languages\ChineseSimplified.isl"
#define BundledZh AddBackslash(InnoDir) + "Languages\ChineseSimplified.isl"
; 有没有中文向导，取决于上面两级来源里能不能找到一个 .isl。[CustomMessages] 里的
; zh_CN.* 键必须跟着它一起出现：Inno 拒绝为 [Languages] 里没有的语言写消息，
; 而直接跑 ISCC 做语法检查时 InnoDir 是空的，只有这条路能让它编得过。
#define HaveZh FileExists(LocalZh) || FileExists(BundledZh)
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
; lzma2/max + solid：139MB 的 one-folder 目录（Qt 与 zeroconf 都在里面）压到约 41MB。
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
; 默认勾上。不勾的后果不是"少一个可选功能"而是这台设备在局域网里彻底隐身，
; 用户不会得到任何提示；勾上的代价只是一次 UAC，拒绝它也不会让安装失败。
Name: "firewall"; Description: "{cm:FirewallTask}"; GroupDescription: "{cm:AdditionalIcons}"

[CustomMessages]
; 任务描述与提示按向导语言各一份；键前缀必须和 [Languages] 的 Name 对得上。
FirewallTask=Let Windows Firewall accept connections from other devices on this LAN (needs admin)
#if HaveZh
zh_CN.FirewallTask=允许 Windows 防火墙放行同一局域网内其它设备的连接（需要管理员权限）
#endif
FirewallSkipped=The firewall rules were not written. ChuanShu will ask Windows for permission the first time it listens; answering that dialog is easy to get wrong - a denial leaves a block rule behind, and Windows obeys a block rule even when an allow rule for the same program exists. Run these commands yourself from an elevated prompt (for each of the two program files, the first one clears whatever is already pinned to it):
#if HaveZh
zh_CN.FirewallSkipped=没有写入防火墙规则。传书第一次监听时 Windows 会弹窗询问，而那个框很容易点错：一旦拒绝过，系统留下的是阻止规则，而 Windows 判定阻止优先——同一个程序就算再加一条允许规则也不会生效。可以稍后在管理员命令提示符里自己执行这几条（窗口与命令行是两个 exe，各自第一条先把钉在那个路径上的旧入站规则清掉）：
#endif

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

[Code]
// [Code] 段里注释只能用 //，分号在这里是语句分隔符而不是注释，写错了编译期就报 'BEGIN' expected。
// 传书靠 mDNS 与 UDP 广播互相发现，而 Windows 防火墙默认拦入站。不放行时首次监听会弹
// 系统授权框，那个框点错一次就再也退不回来：Windows 判定规则时阻止优先于允许，所以只要
// 这个 exe 名下留着一条阻止规则，之后补多少条允许规则都是废纸。安装期把规则写死，让用户
// 根本遇不到那个框。
//
// 本机实测（netsh advfirewall firewall show rule name=all verbose）：系统弹窗点"允许"留下的是
// 按 exe 路径成对的 UDP+TCP 两条入站规则，规则名取 exe 文件名（chuanshu），配置文件只有弹窗时
// 生效的那一个——这台机器的 WLAN 是 Public，所以那四条全是"公用"。"点取消会留下阻止规则"这半句
// 没法在这台机器上复现（要真的拒绝一次系统弹窗，那是写系统的事），所以这里不赌它到底留下什么，
// 直接先把这个路径的入站规则清空再重写：无论留下的是阻止还是允许，结果都一样。

// 清掉钉在这个程序路径上的全部入站规则。删除条件用 name=all + program + dir=in：netsh 的多个过滤
// 条件是求交集的（help 里的例子就是 name=all protocol=tcp localport=80），所以只会命中这个 exe 自己
// 的入站规则——用户给别的程序加的规则、以及这个程序名下的出站规则都不会被碰到。卸载后残留的、指向
// 已删掉的路径的旧规则也不在这里，因为路径对不上。
function ClearInbound(Exe: string): string;
begin
  Result := 'advfirewall firewall delete rule name=all dir=in program="' + Exe + '"';
end;

// 一个程序路径的"先清再放"一对，中间用 cmd 的 & 串起来，所以调用方只需在最前面写一次 netsh。
// 三个配置文件全放，边界交给 remoteip=LocalSubnet 守：手机开热点时 Windows 把这张网卡判成"公用"，
// 只放"专用+域"的规则在传书最主要的使用场景里根本不生效，这条实测过（当前网卡 NetworkCategory=Public）。
// 端口不写死：协议里 transport_default 被占用时会退回临时端口，钉在 43720 的规则那时候就是假的。
function AllowInbound(Exe: string; RuleName: string): string;
begin
  Result := ClearInbound(Exe)
    + ' & netsh advfirewall firewall add rule name="' + RuleName + '" dir=in action=allow'
    + ' profile=any remoteip=LocalSubnet program="' + Exe + '"';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Commands: string;
begin
  if CurStep <> ssPostInstall then Exit;
  if not WizardIsTaskSelected('firewall') then Exit;
  // 窗口和命令行是 {app} 下的两个 exe，而 Windows 按程序路径判规则：只放 ChuanShu.exe 的那台机器，
  // 用 ChuanShu-cli.exe receive 依然连不进来——终端明明在听，局域网对面却是零回应。这条实测过：
  // 同一台机器上 ChuanShu.exe 读出来是放行，ChuanShu-cli.exe 名下压着阻止规则，读出来是挡。
  Commands := AllowInbound(ExpandConstant('{app}\{#AppExeName}'), '{#AppName}')
    + ' & netsh ' + AllowInbound(ExpandConstant('{app}\{#AppCliExeName}'), '{#AppName}-cli');
  // 安装器默认是普通权限（[Setup] PrivilegesRequired=lowest），提权只为了这几条 netsh。
  // 全部命令走同一个 cmd.exe，是为了让用户只看到一次 UAC 框——netsh 命令行一次只吃一条命令，
  // 分几次 ShellExec('runas') 就会问几遍。路径带空格或 & 也没关系：它们在双引号里面，
  // cmd 不会把引号内的 & 当成语句分隔符。
  if not ShellExec('runas', 'cmd.exe', '/c netsh ' + Commands,
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    MsgBox(ExpandConstant('{cm:FirewallSkipped}') + #10#10 + 'netsh ' + Commands,
      mbInformation, MB_OK);
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  // 和安装时同一个删除条件：按程序路径匹配，所以连当初系统弹窗自己建的那对
  // name=chuanshu 规则也一并清掉，不会在防火墙里留下指向已删除文件的僵尸条目。删不掉也照常卸载。
  // 两个 exe 都要清，仍旧走同一个 cmd.exe，所以卸载也只问一次。
  ShellExec('runas', 'cmd.exe',
    '/c netsh ' + ClearInbound(ExpandConstant('{app}\{#AppExeName}'))
    + ' & netsh ' + ClearInbound(ExpandConstant('{app}\{#AppCliExeName}')),
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;
