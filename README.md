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

>> AV/EDR Evasion
>> 

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.
