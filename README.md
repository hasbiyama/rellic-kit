# rellic-kit
This project is a PoC for implementing ReflectiveLoader with a user-mode rootkit.

## Overview

The primary goal of this method is to safely inject the rootkit DLL. It employs the following techniques:

1. **Reflective DLL Injection** (ReflectiveLoader)
2. **Manual Mapping of the DLL**
3. **WMI in C** and **API Hooking**

> **Note:**
> This project needs to compiled with gcc. Please ensure -O3 or -O2 optimisation is used.

## Demo
>> UM Rootkit
>> 
https://github.com/user-attachments/assets/81bbc907-dbd9-4f55-9688-f775993bfac6

>> AV/EDR Evasion
>> 
https://github.com/user-attachments/assets/b4529432-1f00-4a29-9062-739598a88126

## How?

![rellic-kit](https://github.com/user-attachments/assets/f37c3369-c3f0-42bb-a4a2-2aa5d59a8039)


## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.
