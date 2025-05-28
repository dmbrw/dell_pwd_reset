# Dell Password Reset Tool

## About

This an experimental tool that attempts to identify the recovery password for the system (primary) password of various Dell computers.
The primary password is the password associated with the "Dell Security Manager" dialog that appears when the device is booted and the primary password is set.
The recovery password will clear the primary password and also the admininistrator password if it is set (this is the password that if set prevents
any changes being made in the firmware settings).
I have verified its accuracy on several different models (some optiplex, lattitude, inspiron), but I cannot guarantee how general the solution is. 
This tool was developed as a research project and should not be used for illegitimate or illegal purposes.

## Usage

This tool offers a simple CLI with two required arguments:

``` bash
usage: dell_pwd_reset.py [-v/--verbose] [--keep-artifacts] **DeviceString** **PathToFirmwareFile**             

options:
    -v/--verbose            more verbose output
    --keep-artifacts        do not delete extracted firmware filesystems/modules upon completion
```
### DeviceString

The **DeviceString** is the string displayed in the Securty Manager dialog that has the form xxxxxxx-xxxx The first seven of these characters may also
be physically present on the device - they're the service tag. 

### PathToFirmwareFile

The **FirmwareFile** is the path to the boot firmware ("BIOS") for the device. You can find this on the Dell website if you navigate to 
https://www.dell.com/support/home?app=drivers and enter the service tag of the device. 

### Output

The tool will (if successful) provide a string that can be entered into the security manager dialog to reset the password. When enter is pressed to submit 
the password, the capslock key must be toggled and the ctrl key must be held.

## Installation

``` python
pip install -r requirements.txt
```
This will get you the requisite packages. Qiling has a few dependencies (>100mB).

## How it works

The recovery password is determined on the basis of the 11 character string xxxxxxx-xxxx by a particular firmware module. This tool
unpacks the firmware, locates the module and then the specific entry point in the module corresponding to the recovery password generation.
It then executes the module in an emulator at this address, using the user-provided device string (normally the module would obtain the device string
by querying other interfaces). The emulation terminates once the recovery password has been generated, just before it would be compared with the user input to the security manager.
