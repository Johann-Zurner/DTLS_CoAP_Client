# CoAP Client with DTLS Support on Zephyr and WolfSSL

This project implements a CoAP client that communicates securely using DTLS. The client is designed to run on a Nordic board using the Zephyr RTOS.

---

## Features

- **CoAP Protocol**: Implements CoAP (Constrained Application Protocol) for lightweight communication.
- **DTLS Security**: Supports DTLS 1.2 and DTLS 1.3 for encryption and authentication.
- **Authentication**: Works with Pre-Shared Keys (PSK) and certificates.
- **Connection ID (CID)**: Support for DTLS Connection ID to maintain sessions across IP changes.
- **Periodic Messages**: Sends periodic CoAP PUT messages to a specified server.

---

## Requirements

### Hardware
- **Tested Boards**: Nordic Semiconductor nRF9160 (compatibility with other boards is not guaranteed).

### Software
- **nRF Connect for Visual Studio Code**: Set up your environment using the [nRF Connect Getting Started Guide](https://www.nordicsemi.com/Products/Development-tools/nRF-Connect-for-VS-Code/Tutorials#infotabs).
- **WolfSSL**: Instructions to install WolfSSL into Zephyr are down below.

---

## Setup Instructions (nRF Connect for VS Code)
1. Open nRF Connect for Desktop and open Toolmanager
   
![image](https://github.com/user-attachments/assets/667f3e1f-1209-48f3-abf0-a473978082f7)

3. If not yet installed, install the latest nrf Connect SDK (at time of creation of this read.me it was v2.8.0)
4. Download and install WolfSSL crypto library.
   Look for the `west.yml` file. It's usually in the root directory of the NCS installation.  
   **On Windows:** It's located at `C:\ncs\v2.8.0\nrf\west.yml`. Open it with a text editor.

   Add this under *remotes:*:
   ```yaml
   # WolfSSL Repo
   - name: wolfssl
     url-base: https://github.com/wolfssl
   ```
   and this under *projects:*:
   ```yaml
   # WolfSSL master branch
   - name: wolfssl
     path: modules/crypto/wolfssl
     revision: master
    ```
5. Now in the Toolchain manager click update SDK and it will download wolfssl. Alternatively run west update from a nRF Connect terminal
   
      ![image](https://github.com/user-attachments/assets/0da0ce55-8733-4ffa-9537-78676742c32e)
7. Now from toolchain manager open visual studio code
   
![image](https://github.com/user-attachments/assets/6d8ce488-6fc5-4820-a893-cd56e80477cd)
9. 


### 1. Clone the Project
1. Open **Visual Studio Code** with the **nRF Connect extension** installed.
2. Use the **nRF Connect Welcome Page** to open a new terminal.
3. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/CoAP_Client_DTLS.git
   cd CoAP_Client_DTLS
