# Happ for Windows 7 (x64)

[Русский](#русский) | [English](#english)

## Русский

Неофициальный патчер оригинального установщика Happ для Windows 7 SP1 x64.

### Что делает патчер

- Изменяет проверку версии Windows 10 build 15063 на Windows 7 build 7600.
- Добавляет установщик VxKex 1.2.2.2316 и запускает его автоматически.
- Настраивает VxKex для `Happ.exe`, `happd.exe`, `xray.exe`, `tun2proxy-bin.exe` и установщика обновлений.

### Поддерживаемые режимы TUN

В Windows 7 работают только следующие режимы TUN:

- **Xray TUN**
- **tun2proxy**

Другие режимы TUN не поддерживаются.

### Использование

Требуется Python 3.10+.

Рядом со скриптом должен находиться файл:

```text
KexSetup_Release_1_2_2_2316.exe
```

Запуск:

```bat
py HappPatcherPlus_Win7.py setup-Happ.x64.exe
```

Готовый установщик сохраняется рядом со скриптом с суффиксом `_win7`.

Можно указать пути вручную:

```bat
py HappPatcherPlus_Win7.py "input.exe" "output.exe"
```

### Установка

Скачайте готовый установщик из [Releases](https://github.com/arz321/happ-desktop-windows-7/releases) и запустите от имени администратора.

Проект неофициальный. Совместимость зависит от версии Happ, VxKex, драйверов и конфигурации Windows.

---

## English

An unofficial patcher for the original Happ installer, intended for Windows 7 SP1 x64.

### What it does

- Patches the OS-version check from Windows 10 build 15063 to Windows 7 build 7600.
- Bundles VxKex Setup 1.2.2.2316 and runs it automatically.
- Configures VxKex for `Happ.exe`, `happd.exe`, `xray.exe`, `tun2proxy-bin.exe`, and the Happ updater.

### Supported TUN modes

Only the following TUN modes work on Windows 7:

- **Xray TUN**
- **tun2proxy**

Other TUN modes are not supported.

### Usage

Python 3.10 or later is required.

Place this file next to the patcher:

```text
KexSetup_Release_1_2_2_2316.exe
```

Run:

```bat
py HappPatcherPlus_Win7.py setup-Happ.x64.exe
```

The patched installer is saved beside the script with the `_win7` suffix.

You can also specify both paths manually:

```bat
py HappPatcherPlus_Win7.py "input.exe" "output.exe"
```

### Installation

Download the installer from [Releases](https://github.com/arz321/happ-desktop-windows-7/releases) and run it as administrator.

This is an unofficial project. Compatibility depends on the Happ version, VxKex, drivers, and Windows configuration.
