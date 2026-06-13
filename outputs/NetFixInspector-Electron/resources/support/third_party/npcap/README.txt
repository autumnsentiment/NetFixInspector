Npcap OEM installer drop-in directory
=====================================

Put your licensed Npcap OEM redistribution installer here before building the
Electron package, for example:

  work\netfix_electron\third_party\npcap\npcap-oem.exe

The Electron build script copies matching npcap*.exe files into:

  resources\support\third_party\npcap\

The desktop UI then prefers the bundled installer when the user clicks
"安装内置 Npcap".

Do not place the public/free Npcap installer here for redistribution unless
your Npcap license permits bundling it with this product.
