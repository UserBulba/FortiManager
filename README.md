# PowerFortiManager

![FMG_PS](Image/logo.png)

This tool allows you to easily interact with the FMG API via Powershell to automate tasks performed on FortiGate devices.

Example of usage **GetDevice** function:

```powershell
Login -FortiManager 1.2.3.4
$Data = GetDevice -adom "root" -device "Dummy"
Write-Output $Data.result.data
```
