# Happ - Proxy Utility

Happ is a mobile application designed for convenient proxy server management, powered by the robust Xray core. The app features an intuitive interface and a range of useful functions, making it an essential tool for managing connections.

**Key features of Happ include:**

* Configuration of proxy servers based on flexible routing rules.
* Support for multiple modern protocols, including:
  * **VLESS (Reality)**
  * **VMess**
  * **Trojan**
  * **Shadowsocks**
  * **Socks**

Happ ensures your network activity remains private by not collecting any data; your information remains solely on your device without being sent to external servers.

It's important to highlight that Happ does not provide VPN services for purchase. Users are responsible for acquiring or setting up their own servers. Users should also comply with applicable laws in their jurisdiction when utilizing the app.

To report a problem, use our [service](https://issues.happ.su/)

# Install Happ for Windows 7

We will need [**VxKex Version 1_2_1_2229**](https://github.com/i486/VxKex/releases/download/Version1.2.1.2229/KexSetup_Release_1_2_1_2229.exe) and two additional libraries. You can either download them or extract them from the **System32** folder on Windows 10, but only specific versions of these libraries will work.

* [**msvcp_win.dll**](https://dll-files.com/msvcp_win.dll.html) version **10.0.18362.387**
  SHA-1: `ba886908d65f143131eff45ae07471038ecf3c81`

* [**icuuc.dll**](https://dllme.com/dll/files/icuuc/30777215e80989bc5ecf1fc27987c83b) version **72.1.0.2 (WinBuild.160101.0800)**
  SHA-1: `c67fc39cf249295a2900d867e490ceb1a873e165`

We also need Xray and tun2proxy builds for Windows 7.

* [**Xray-win7-64.zip**](https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-win7-64.zip) version: **26.6.27 (45cf289)**
  SHA-1: `84eedb589d03f7689f10fdb0a242eb135484a07d`

* [**tun2proxy-x86_64-win7-windows-msvc.zip**](https://github.com/tun2proxy/tun2proxy/releases/download/v0.7.15/tun2proxy-x86_64-win7-windows-msvc.zip) version: **0.7.15 (748f999 2025-09-09 06:08:31)**
  SHA-1: `d3eeb008863672abd8b4950ddb1797a688cdb232`

All these files can be found in the [**release**](https://github.com/arz321/happ-desktop-windows-7/releases).

1. Download and install [**VxKex**](https://github.com/i486/VxKex/releases/download/Version1.2.1.2229/KexSetup_Release_1_2_1_2229.exe).
2. Download the [Happ installer](https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe)/[mirror](https://files-hub.com/download/windows/latest?arch=x64). In the properties of `setup-Happ.x64.exe`, open the **VxKex** tab and enable the following options:

   * **Enable VxKex for this program**
   * **Report a different version of Windows**
   * **Then select **Windows 10** from the list.**

3. Install `setup-Happ.x64.exe` and ignore any errors that may appear.
4. Open the folder where Happ was installed and extract the contents of [**happ_win7.zip**](https://github.com/arz321/happ-desktop-windows-7/releases/download/Release/happ_win7.zip) into it, replacing the existing files (`msvcp_win.dll`, `icuuc.dll`, the `core` folder and the `tun2` folder).
5. Run `HappVxKexSetup.bat`. It will automatically configure VxKex compatibility settings for the following executables:

   * `%ProgramFiles%\FlyFrogLLC\Happ\Happ.exe` → Windows 10 mode
   * `%LOCALAPPDATA%\Happ\update\setup-Happ.x64.exe` → Windows 10 mode
   * `%ProgramFiles%\FlyFrogLLC\Happ\core\xray.exe` → Windows 7 mode
   * `%ProgramFiles%\FlyFrogLLC\Happ\tun2\tun2proxy-bin.exe` → Windows 7 mode
   * It will also enable the **"Run this program as an administrator"** compatibility option for `Happ.exe`, which is required for tun2proxy to function correctly.

If you encounter the error **"Failed to initialize graphics backend D3D11"**, you need to change the Happ UI rendering settings in the Windows registry.

   * For **OpenGL** rendering, run `OpenGL.reg`.
   * For **CPU (software)** rendering, run `Software.reg`.

# Limitations Happ for Windows 7
TUN mode works with tun2proxy, but it's extremely unstable at startup. It also doesn't work with Histeria.
