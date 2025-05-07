# gridd-unlock-patcher

> [!note] Credits
> This code is built by `electricsheep49`. The Windows replacement script is written by `lcs`.

**Only Linux is supported for executing the patcher**,
see **[Releases](https://git.collinwebdesigns.de/oscar.krause/gridd-unlock-patcher/-/releases)**.

The patcher supports both, Windows and Linux guests:

- For Windows guests, the GRID daemon is Display.Driver/nvxdapix.dll
- For Linux guests, execute `which nvidia-gridd` to find your GRID daemon. It's probably in `/bin/`.

# How to patch

**Prepare**

1. Download [latest release](https://git.collinwebdesigns.de/oscar.krause/gridd-unlock-patcher/-/releases)
2. Make executable `chmod +x gridd-unlock-patcher`
3. Download your *FastAPI-DLS Root-CA* from `https://<your-dls-url>/-/config/root-certificate`

## Linux

*This overwrites the given binary, make sure you have a backup!*

1. Run patch `gridd-unlock-patcher -g $(which nvidia-gridd) -c /path/to/my_root_certificate.pem`
2. Restart `nvidia-gridd` service

## Windows

*This overwrites the given dll, make sure you have a backup!*

1. Download [`windows-replace-nvxdapix.ps1`](windows-replace-nvxdapix.ps1) (written by `lcs`) to the Desktop of your
   Windows machine
2. Run
   `Get-ChildItem -Path "C:\Windows\System32\DriverStore\FileRepository" -Recurse -Filter "nvxdapix.dll" -ErrorAction SilentlyContinue | Select-Object -First 1`
3. Copy the `nvxdapix.dll` from the resulting path to your Linux host where the `gridd-unlock-patcher` is installed
4. Run patch `gridd-unlock-patcher -g /path/to/nvxdapix.dll -c /path/to/my_root_certificate.pem`
5. Copy the patched `nvxdapix.dll` back to the Desktop of your Windows machine
6. Run `powershell.exe -executionpolicy bypass -file "$HOME\Desktop\gridd-apply-patch.ps1"` as Administrator

*Maybe one patched DLL per Driver-Release can be copied across all Windows machines matching the same Driver-Release!*

Output should look like

```shell
PS C:\WINDOWS\system32> powershell.exe -executionpolicy bypass -file "$HOME\Desktop\gridd-apply-patch.ps1"
Searching for nvxdapix.dll in C:\Windows\System32\DriverStore\FileRepository...
Found DLL: C:\Windows\System32\DriverStore\FileRepository\nvgridsw.inf_amd64_847af0d59d1a7293\nvxdapix.dll
Replaced nvxdapix.dll successfully.
PS C:\WINDOWS\system32>
```
