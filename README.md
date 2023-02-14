# OSS - Kemper Profiler

Work In Progress

* Goal
  * create a shared module that exports a "C" interface
  * Used from the following languages
    * C/C++
    * Rust
    * Dart

## Runtime Pre-requisites
* Ubuntu

      sudo apt-get install -y libusb-1.0-0-dev

* Fedora

      sudo dnf install libusb1-devel

## Linux Setup

Create USB Device rule to prevent needing `sudo` to access device.

* Create a USB device rule file

      /etc/udev/rules.d/75-kemper.rules

* Add to file

      SUBSYSTEM=="usb", ATTRS{idVendor}=="133e", ATTRS{idProduct}=="0001", TAG+="uaccess"

* Reload udevadm

      sudo udevadm control --reload-rules && sudo udevadm trigger


## profiler_cli

### Status

* Hardcoded to Profiler Stage (133e:0001)
* Connects to Profiler Stage
* Emulates basic connection with Rig Manager
* prints out received packets

### Use Control + C to exit
