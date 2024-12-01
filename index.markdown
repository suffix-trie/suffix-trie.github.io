---
layout: page
title: Reverse engineering Tenways' firmware
permalink: /
---

### Section 1 - Introduction
The goal of this guide is to reverse engineer the firmware of the Tenways CGO600 and CGO600 Pro displays in order to remove the software speed limit. No invasive procedures, such as opening the display casing or intercepting communication packets, are required. 

# Disclaimer
1. Modifying the firmware of your e-bike to exceed legally prescribed speed limits is illegal in many countries and regions. Riding an e-bike that exceeds the legal speed limit (typically 25 km/h in many places) on public roads is against the law. If you choose to modify your e-bike, you do so at your own risk and accept full responsibility for any legal consequences, including fines, citations, or criminal charges. Always check your local laws and regulations regarding e-bike modifications before proceeding. The author of this guide is not responsible for any illegal activities or accidents that occur as a result of following this guide. 

2. Increasing the maximum speed of your e-bike can significantly affect its safety, including braking distance, stability, and rider control. Riding an e-bike faster than it was designed for can result in accidents, injury, or death. Ensure that your bike's components (brakes, tires, etc.) are properly rated for higher speeds, and always wear appropriate protective gear when riding. If in doubt, consult with a professional mechanic or technician before attempting modifications.

3. By modifying the firmware to bypass safety limits, you are assuming responsibility for the risks involved. Not only could you be violating traffic laws, but you also expose yourself to the possibility of liability in the event of an accident. You should never modify the firmware for use on public roads or in situations where it could endanger others. This guide is intended for educational purposes only and should be used with caution and a clear understanding of the consequences of any modifications.

4. This guide is intended for educational purposes, and the information provided here is meant to help you understand the technical aspects of firmware modification. We strongly recommend using this knowledge only in private or controlled environments where safety and legality are not a concern, such as private tracks or testing areas. Do not use a modified ebike in public areas unless you are certain it complies with local laws.

5. By following this guide, you acknowledge that you understand the legal and safety risks involved in modifying your ebike's firmware. The author is not liable for any damages, injuries, or legal issues that may arise as a result of following these instructions. Always proceed with caution and consider the potential consequences before making modifications to your e-bike.

# Outline of how to achieve the goal
1. Obtain the firmware of the display.
2. Decompile it using [Ghidra](https://ghidra-sre.org/){:target="_blank"}.
3. Find the part of the code that sets the speed limit.
4. Change the assembly instructions of that function to remove the speed limit.
5. Upload the modified firmware to the bike's display via Bluetooth.

# CGO600 system
The CGO600 and CGO600 Pro models have basically the [same parts](https://www.tenways.com/pages/comparison){:target="_blank"}. For the purpose of this guide, they can be considered the same, so from now on we will use "CGO600" to refer to both models. 

The CGO600 ebike system has two components that interest us: the SW102 display and the motor controller. They communicate over [UART](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter){:target="_blank"}. The maximum speed is sent by the display to the motor controller. We will modify the code of the SW102 display to send an arbitrary maximum speed.

![](assets/ebike-system.001.jpeg)

### Section 2 - Obtain the firmware of the display
Our first step is to obtain the firmware that is running on the display. Normally, we would have to connect via [j-link](https://wiki.segger.com/Main_Page){:target="_blank"} directly to the pins of the device to extract the firmware. However, we were fortunate that Tenways released their firmware online [here](https://tenways.zendesk.com/attachments/token/z8piZJtAIPiQ8BvcSvtylzwfE/?name=SW102-CGO600.zip){:target="_blank"}. 

The firmware we downloaded is packaged as a zip file with the following contents:
```
manifest.json
sw102.bin
sw102.dat
```
The file we are interested in is `sw102.bin`, which contains the firmware in binary format.

### Section 3 - Decompile the firmware using Ghidra

Before you follow this section, download and install [Ghidra](https://ghidra-sre.org/) on your computer. 

Open Ghidra and create a new project. You should see this window:


![](assets/ghidra-new-project.jpg) 


Now import the binary firmware we downloaded earlier: select File -> Import File -> sw102.bin.
As "Language", select "ARM Cortex Little Endian" because the SW102 display uses a Nordic nrf52 chip which has a little endian ARM Cortex CPU.


![](assets/ghidra-import-file.jpg)


Now double click on the imported file. A new ghidra window opens and prompts us whether we would like to analyze the binary. Select "Yes". A new window called "Analysis Options" opens. In addition to the default options, select "ARM aggressive instruction finder (Prototype)". Click "Analyze".


![](assets/ghidra-analyze.jpg)


Once Ghidra finishes the analysis, you will see the assembly instructions in the middle of the window, and the decompiled C-like code on the right:


![](assets/ghidra-opened.jpg) 


### Section 4 - Find the part of the code that sets the speed limit

Thanks to the author of this [Github repository VELOX](https://github.com/SenneRoot/VELOX){:target="_blank"} we discovered that the identifier for setting the maximum wheel RPM is [0x1F](https://github.com/SenneRoot/VELOX/blob/main/Firmware/VELOX/src/Controller/MiviceC201.h){:target="_blank"}. The communication packet that sets the max speed looks like this: 


![](assets/max-rpm-packet.jpeg)


To find the location where this packet is created, we can search for "0x1f" in the firmware. One of the results will be the function that creates this packet. Go to Ghidra, select Search -> Scalar and type 0x1f in "specific scalar":


![](assets/ghidra-search-scalar.jpg)


We get 92 hits:


![](assets/ghidra-search-results.jpg)


We go through the results. We find this very promising function that contains the "Set" code 0x16, and "Max RPM" 0x1f:


![](assets/ghidra-found-function-0x1f.jpg)


At first glance, it looks like it is filling a buffer with the communication codes. Let's rename some variables to make it clearer (to rename a variable in Ghidra, right click it and select "Rename"):


![](assets/ghidra-fil-buffer-fn.jpg)


We could modify the instructions of `fill_buffer_according_to_comm_id`, but since the `if` at line 18 is true when `comm_code == 0x1c || comm_code == 0x1f` and we don't know what `0x1c` is used for, we can play it safe by modifying the code where `fill_buffer_according_to_comm_id` gets called with `comm_code = 0x1f`.
To find this location, we can search for references to `fill_buffer_according_to_comm_id` (to find references to a function, right click it and select "References" -> "Find references to function"). We get only three results. One is what we are looking for:


![](assets/ghidra-references-to-fn.jpg)


We rename and retype the variables in this function as well. We obtain this:


![](assets/ghidra-sent-max-rpm.jpg)


The lines of this function we are interested in are lines 19-20:
```c
// call get_max_RPM, and save the result in max_RPM 
max_RPM = get_max_RPM();
// the data used to set the maximum RPM consists of 2 bytes: 
// the high and the low byte of max_RPM
max_RPM_data._0_2_ = CONCAT11((char)max_RPM, (char)max_RPM>>8); 
```
In the next section, we will modify these two lines to set the speed limit to our liking.


### Section 5 - Modify the firmware

We would like to modify the code we found in the previous section to look like this:
```c
max_speed = 50km/h
max_RPM_data[0..2] = rpm_of(max_speed)
```

What values should be written to `max_RPM_data`? We can determine this by looking at the following code from the [VELOX Github repository](https://github.com/SenneRoot/VELOX){:target="_blank"}:

```
void MiviceC102Driver::calculateRPM(double speed, byte& b1, byte& b2)
{
  unsigned int res = ceil((speed * 1000)/(2.18 * 60));
  b1 = res >> 8;   // shift the higher 8 bits
  b2 = res & 0xff; // mask the lower 8 bits
}
```

Let's say we want to set the speed limit to 50 km/h. In reality we will never reach 50km/h because the motor is not powerful enough, so it will just never cut off. We can create this C++ program and find out the value of b1 and b2:
```
#include <iostream>
#include <cstdint>
#include <cmath>
#include <iomanip>

void calculateRPM(double speed, uint8_t& b1, uint8_t& b2)
{
  unsigned int res = ceil((speed * 1000)/(2.18 * 60));
  b1 = res >> 8;   // shift the higher 8 bits
  b2 = res & 0xff; // mask the lower 8 bits
}

int main() {
    uint8_t b1, b2 = 0;
    calculateRPM(50, b1, b2);
    
    std::cout << std::hex << "b1 is: " << static_cast<int>(b1) << " b2 is: " << static_cast<int>(b2) << "\n";

    return 0;
}

>>> b1 is: 1 b2 is: 7f
```

The ideal code we need is therefore:
```c
max_RPM_data[0] = 0x1;
max_RPM_data[1] = 0x7f;
```


Our max RPM packet that sets the limit to 50km/h will look like this:


![](assets/max-rpm-packet-50kmh.001.jpeg)


Back to Ghidra now. By clicking on line 20 of the decompiled code, we can see the corresponding assembly instructions on the left view. These are the instructions that load the max RPM:


![](assets/ghidra-original-assembly.jpg)


We explain what the most important instructions do:

```c
# call get_max_RPM. Result is stored in max_RPM.
bl get_max_RPM 
# load register r1 with max_RPM shifted 8 bits to the right (high byte).
lsrs r1, max_RPM, 0x8
# copy the stack pointer (sp) to r2. The stack pointer points to max_RPM_data,
# so now r2 is max_RPM_data.
mov r2, sp
# store r1 at max_RPM_data[0]
strb r1, [r2,0x0]
# store the low byte of max_RPM at max_RPM_data[1]
strb max_RPM, [r2,0x1]
```

By using the "patch instruction" function of Ghidra (right click on an instruction and select "Patch instruction"), we can replace the above assembly with the following to load `0x01` and `0x7f` into `max_RPM_data`:

```c
# copy the stack pointer (sp) to r2. The stack pointer points to max_RPM_data,
# so now r2 is max_RPM_data.
mov r2, sp
# r1 = 0x1
movs r1, 0x1
# max_RPM_data[0] = r1
strb r1, [r2, 0x0]
# r1 = 0x7f
movs r1, 0x7f
# max_RPM_data[1] = r1
strb r1, [r2, 0x1]
# no-operation - padding to maintain the same length as the original code.
nop
```

Here's what the modified code looks like in Ghidra:


![](assets/ghidra-modified-assembly.jpg)
![](assets/ghidra-decompiled-modified-fn.jpg)


All that is left to do now is to export the modified version to binary format so we can upload it to the bike. Select File -> Export Program... Use "Raw bytes" as format and "sw102.bin" as name.
Done! We have an executable binary that will set the limit to 50km/h!

### Section 6 - Upload the modified firmware to the bike's display via Bluetooth

In the previous section, we modified sw102.bin to remove the speed limit. Now we will upload it to the ebike. Open the folder that contained the original sw102.bin file and replace sw102.bin with the modified version. There should be the following three files in the folder:
```c
manifest.json
sw102.bin // binary modified with Ghidra
sw102.dat
```
We cannot upload this directly because Nordic’s DFU (Device Firmware Update) protocol uses a CRC value to verify that all bytes have been uploaded correctly. The CRC values is stored in `manifest.json` and in `sw102.dat`. We will first compute the new CRC, and then modify `manifest.json` and `sw102.dat` to contain the new CRC.

The CRC is [computed by Nordic](https://github.com/NordicSemiconductor/pc-nrfutil/blob/16cb5a3d352bcc7a3ddbbf541426e3cca0f34671/nordicsemi/dfu/crc16.py){:target="_blank"}'s nrf-util tool with the following function:
```python
def calc_crc16(binary_data: bytes, crc=0xffff):
    """
    Calculates CRC16 on binary_data

    :param int crc: CRC value to start calculation with
    :param bytearray binary_data: Array with data to run CRC16 calculation on
    :return int: Calculated CRC value of binary_data
    """

    for b in binary_data:
        crc = (crc >> 8 & 0x00FF) | (crc << 8 & 0xFF00)
        crc ^= ord(b)
        crc ^= (crc & 0x00FF) >> 4
        crc ^= (crc << 8) << 4
        crc ^= ((crc & 0x00FF) << 4) << 1
    return crc & 0xFFFF
```
Let's ask ChatGPT to create a python program that calculates the CRC of a binary file using this function. Here's what it came up with:
```python
import sys

def calc_crc16(binary_data: bytes, crc=0xffff):
    for b in binary_data:
        crc = (crc >> 8 & 0x00FF) | (crc << 8 & 0xFF00)
        crc ^= b # was ord(b) originally
        crc ^= (crc & 0x00FF) >> 4
        crc ^= (crc << 8) << 4
        crc ^= ((crc & 0x00FF) << 4) << 1
    return crc & 0xFFFF

def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def main():
    if len(sys.argv) != 2:
        print("Usage: python crc_calculator.py <binary_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        binary_data = read_file(file_path)
        crc_value = calc_crc16(binary_data)

        little_endian_crc = (crc_value & 0xFF) << 8 | (crc_value >> 8)
        print(f"CRC16 for file '{file_path}': decimal: {crc_value} hex little endian: {little_endian_crc:04X}")
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

Let's run the program with the modified firmware path as argument:
```
>>> python3 crc_calculator.py SW102-CGO600/sw102.bin

CRC16 for file 'SW102-CGO600/sw102.bin': decimal: 62599 hex little endian: 87F4
```
The CRC value is `62599` in decimal notation and `0x87f4` in hexadecimal little endian. If you get a different value, it means that your modified firmware is different from the one in this guide. If you think you have done everything exactly like this guide, you should go back and check the previous steps. Let's replace the old CRC value in `manifest.json` and `sw102.dat` with this new one.

`manifest.json` is easy to modify. We can open it with a text editor and update the `firmware_crc16` json property:
```json
{
    "manifest": {
        "application": {
            "bin_file": "sw102.bin",
            "dat_file": "sw102.dat",
            "init_packet_data": {
                "application_version": 4294967295,
                "device_revision": 65535,
                "device_type": 65535,
                "firmware_crc16": 62599,
                "softdevice_req": [
                    100
                ]
            }
        },
        "dfu_version": 0.5
    }
}
```

`sw102.dat` is a binary file. We can open it with an hex editor:


![](assets/crc-sw102-dat-original.jpg)


the last bytes `0x78, 0xfa` are the old crc. We can replace them with the new crc `0x87, 0xf4`:


![](assets/crc-sw102-dat-modified.jpg)


The last thing we need to do is zip the three modified files. Make sure to zip the three files and not the folder that contains them.

```
>>> zip -r sw102-hacked.zip manifest.json sw102.bin sw102.dat
adding: manifest.json (deflated 61%)
adding: sw102.bin (deflated 39%)
adding: sw102.dat (deflated 14%)
```
Send the zip archive to your phone. 
On your phone download and open the ["DFU updater"](https://www.nordicsemi.com/Products/Development-tools/nRF-Device-Firmware-Update){:target="_blank"} app. Select the .zip archive you sent from your computer. Select your ebike as device. Upload.

![](assets/upload-success.jpg)


That's it! Now your Tenways CGO600 or CGO600 Pro is not software limited anymore!

### Additional information

If you could not follow all the steps, or you want to verify them, you can download the modified firmware package [here](assets/sw102-hacked.zip). And upload it to your ebike with the ["DFU updater"](https://www.nordicsemi.com/Products/Development-tools/nRF-Device-Firmware-Update){:target="_blank"} app as described above.

Did you enjoy this guide? Buy me a coffee! I would really appreciate it!
<div style="text-align: center;">
  <a href="https://www.buymeacoffee.com/suffix_trie" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
</div>
<br>

Do you have a question or comment? Email me: `pyrites_loudest0q at icloud dot com`