---
layout: page
title: Reverse engineering Tenways' firmware
permalink: /
---

# Goal
Our goal is to learn how to reverse engineer the firmware of the Tenways CGO600 and CGO600 Pro's display, and remove the software speed limit. 

# Disclaimer
1. Riding an ebike that is not limited to 25 km/h is illegal and dangerous. You should never do it on public roads. If you choose to break the law and ride faster than 25 km/h, you do so at your own risk. 
2. Uploading modified firmware to the ebike's display can potentially break it. In that case, you will have to buy a new display from Tenways. If you choose to upload modified firmware to your ebike, you do so at your own risk.
3. We take no responsibility for any fines or accidents resulting from you riding faster than 25 km/h, or for any broken displays.

# Outline of how to achieve the goal
1. Get the firmware of the CGO600 and CGO600 Pro's display.
2. Decompile it using [Ghidra](https://ghidra-sre.org/).
3. Find the function that sets the speed limit.
4. Change the assembly instructions of that function to remove the speed limit.
5. Upload the modified firmware to a bike.
6. Revert the firmware to the original.