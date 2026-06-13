Npcap installer placeholder
===========================

NetFixInspector loads Npcap dynamically at runtime, but this package does not include the Npcap driver installer.

Why:
- The public/free Npcap installer is not meant to be redistributed inside third-party product packages.
- To bundle and silently install Npcap with your own product, use a licensed Npcap OEM redistribution installer.

How to use this folder:
1. Put your licensed Npcap OEM installer here, for example npcap-oem.exe.
2. Run Install-Npcap.bat.
3. For OEM silent install, run:
   powershell -ExecutionPolicy Bypass -File .\Install-Npcap.ps1 -Silent

Without an OEM installer, Install-Npcap.bat opens the official Npcap download page so the user can install it manually.
