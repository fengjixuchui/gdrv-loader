# gdrv-loader
Kernel driver loader using vulnerable driver gigabyte driver (https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities) to load a unsigned driver.

## usage
open command prompt as admin, run command 

gdrv-loader.exe gdrv.sys driver.sys to load unsigned driver

gdrv-loader.exe driver.sys to unload unsigned driver
