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

We will need [**VxKex Version 1.1.4.1588**](https://github.com/i486/VxKex/releases/download/Version1.1.4.1588/KexSetup_Release_1_1_4_1528.exe) and two additional libraries. You can either download them or extract them from the **System32** folder on Windows 10, but only specific versions of these libraries will work.

* [**msvcp_win.dll**](https://dll-files.com/msvcp_win.dll.html) version **10.0.18362.387**
  SHA-1: `ba886908d65f143131eff45ae07471038ecf3c81`

* [**icuuc.dll**](https://dllme.com/dll/files/icuuc/30777215e80989bc5ecf1fc27987c83b) version **72.1.0.2 (WinBuild.160101.0800)**
  SHA-1: `c67fc39cf249295a2900d867e490ceb1a873e165`

1. Download and install **VxKex**.
2. Download the [Happ installer](https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe)/[mirror](https://files-hub.com/download/windows/latest?arch=x64). In the properties of `setup-Happ.x64.exe`, open the **VxKex** tab and enable the following options:

   * **Enable VxKex for this program**
   * **Report a different version of Windows**
   * **Then select **Windows 10** from the list.**

3. Install `setup-Happ.x64.exe` and ignore any errors that may appear.
4. Open the folder where Happ was installed, copy `msvcp_win.dll` and `icuuc.dll` into that folder, then open the properties of `Happ.exe` and, just as in step 2, select **Windows 10** and launch the application.

If you encounter the error **"Failed to initialize graphics backend D3D11"**, you need to change the Happ UI rendering settings in the Windows registry.

Run the following command in `cmd.exe`:

For **OpenGL** rendering:

```cmd
reg add "HKCU\Software\Happ\OrganizationDefaults\Preferences" /v "graphicsBackend" /t REG_SZ /d "OpenGL" /f
```

Or, for **CPU (software)** rendering:

```cmd
reg add "HKCU\Software\Happ\OrganizationDefaults\Preferences" /v "graphicsBackend" /t REG_SZ /d "Software" /f
```
# Limitations Happ for Windows 7

I managed to get TUN mode working with tun2proxy, but it is extremely unstable. To enable it, you need to replace Xray and tun2proxy binaries with builds with Windows 7, and then select Windows 7 in the VxKex properties.

