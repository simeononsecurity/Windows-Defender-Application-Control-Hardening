# Windows-Defender-Application-Control-Hardening

[![VirusTotal Scan](https://github.com/simeononsecurity/Windows-Defender-Application-Control-Hardening/actions/workflows/virustotal.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Defender-Application-Control-Hardening/actions/workflows/virustotal.yml)

This is a PowerShell script that configures Windows Defender Application Control (WDAC) on a Windows machine. The script requires elevated privileges to run and continues even if errors are encountered. It creates a new "Temp" directory in the C:\ drive and copies necessary Windows Defender configuration files to it. The script then enables WDAC by importing policies and adding necessary services. The script also enables the Intelligent Security Graph (ISG) and Managed Installer (MI) diagnostic events for troubleshooting. The script ends with a prompt to the user to restart the computer to make changes effective.

## Notes:
- Windows Server 2016/2019 or anything before version 1903 only support a single legacy policy at a time.
- Windows Server Core edition supports WDAC but some components that depend on AppLocker won’t work
- Please read the [Recommended Reading](https://github.com/simeononsecurity/Windows-Defender-Application-Control-Hardening#recommended-reading) before implementing or even testing.

## A list of scripts and tools this collection utilizes:

- [MicrosoftDocs - WDAC-Toolkit](https://github.com/MicrosoftDocs/WDAC-Toolkit)
- [Microsoft - Refresh CI Policy ](https://www.microsoft.com/en-us/download/details.aspx?id=102925)

## Additional configurations were considered from:

- [Microsoft - Recommended block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
- [Microsoft - Recommended driver block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [Microsoft - Windows Defender Application Control](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide)

## Explanation:

### XML vs. BIN:

- Simply put, the **"XML"** policies are for applying to a machine locally and the **"BIN"** files are for enforcing them with either [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy) or [Microsoft Intune](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-intune). While you can use XML, BIN, or CIP policies in a local deployment, generally speaking you should stick to XML where possible and especially so while auditing or troubleshooting.

### Policy Descriptions:

- **Default Policies:**
  - The "Default" policies use only the default features available in the WDAC-Toolkit.
- **Recommended Policies:**
  - The "Recommended" policies use the default features as well as Microsoft's recommended [blocks](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules) and [driver block](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) rules.
- **Audit Policies:**
  - The "Audit" policies, just log exceptions to the rules. This is for testing in your environment, so that you may modify the policies, at will, to fit your environments needs.
- **Enforced Policies:**
  - The "Enforced" policies will not allow any exceptions to the rules, applications, drivers, dlls, etc. will be blocked if they do not comply.

### Available Policies:

- **XML:**
  - **Audit Only:**
    - `WDAC_V1_Default_Audit.xml`
    - `WDAC_V1_Recommended_Audit.xml`
  - **Enforced:**
    - `WDAC_V1_Default_Enforced.xml`
    - `WDAC_V1_Recommended_Enforced.xml`
- **BIN:**
  - **Audit Only:**
    - `WDAC_V1_Default_Audit.bin`
    - `WDAC_V1_Recommended_Audit.bin`
  - **Enforced:**
    - `WDAC_V1_Default_Enforced.bin`
    - `WDAC_V1_Recommended_Enforced.bin`
- **CIP:**
  - **Audit Only:**
    - `WDAC_V1_Default_Audit\{uid}.cip`
    - `WDAC_V1_Recommended_Audit\{uid}.cip`
  - **Enforced:**
    - `WDAC_V1_Default_Enforced\{uid}.cip`
    - `WDAC_V1_Recommended_Enforced\{uid}.cip`

Update the following line in the script to use the policy that you desire locally:

```powershell
$PolicyPath = "C:\temp\Windows Defender\CIP\WDAC_V1_Recommended_Enforced\*.cip"
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
ForEach ($Policy in (Get-ChildItem -Recurse $PolicyPath).Fullname) {
  $PolicyBinary = "$Policy"
  $DestinationFolder = $env:windir+"\System32\CodeIntegrity\CIPolicies\Active\"
  $RefreshPolicyTool = "./Files/EXECUTABLES/RefreshPolicy(AMD64).exe"
  Copy-Item -Path $PolicyBinary -Destination $DestinationFolder -Force
  & $RefreshPolicyTool
}
```

Alternatively, you may use [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy) or [Microsoft Intune](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-intune) to enforce the WDAC policies.

## Auditing:

You can view the WDAC event logs in event viewer under:

`Applications and Services Logs\Microsoft\Windows\CodeIntegrity\Operational`

## Recommended Reading:

- [Argonsys - Deploying Windows 10 Application Control Policy](https://argonsys.com/microsoft-cloud/library/deploying-windows-10-application-control-policy/)
- [Microsoft - Audit Windows Defender Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/audit-windows-defender-application-control-policies)
- [Microsoft - Create a WDAC policy for fixed-workload devices using a reference computer](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/create-initial-default-policy)
- [Microsoft - Deploy Windows Defender Application Control policies by using Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy)
- [Microsoft - Deploy Windows Defender Application Control policies by using Microsoft Intune](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-intune)
- [Microsoft - Deploy WDAC policies using script](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script)
- [Microsoft - Enforce Windows Defencer Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/enforce-windows-defender-application-control-policies)
- [Microsoft - Guidance on Creating WDAC Deny Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/create-wdac-deny-policy)
- [Microsoft - Use multiple Windows Defender Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-multiple-windows-defender-application-control-policies)

## How to run the script:

### Manual Install:

If manually downloaded, the script must be launched from an administrative powershell in the directory containing all the files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Defender-Application-Control-Hardening/archive/main.zip)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
Get-ChildItem -Recurse *.ps1 | Unblock-File
.\sos-wdachardening.ps1
```


<a href="https://simeononsecurity.ch" target="_blank" rel="noopener noreferrer">
  <h2>Explore the World of Cybersecurity</h2>
</a>
<a href="https://simeononsecurity.ch" target="_blank" rel="noopener noreferrer">
  <img src="https://simeononsecurity.ch/img/banner.png" alt="SimeonOnSecurity Logo" width="300" height="300">
</a>

### Links:
- #### [github.com/simeononsecurity](https://github.com/simeononsecurity)
- #### [simeononsecurity.ch](https://simeononsecurity.ch)
