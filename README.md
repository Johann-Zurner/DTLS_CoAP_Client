# CoAP Client with DTLS Support on Zephyr and WolfSSL

This project implements a CoAP client that communicates securely using DTLS. The client is designed to run on a Nordic board using the Zephyr RTOS. The whole setup is designed to test the functionality of Connection ID.

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
- **Tested Boards**: Nordic Semiconductor nRF9160DK (compatibility with other boards unknown).

### Software
- **nRF Connect for Visual Studio Code**: Set up your environment using the [nRF Connect Getting Started Guide](https://www.nordicsemi.com/Products/Development-tools/nRF-Connect-for-VS-Code/Tutorials#infotabs).
- **WolfSSL**: Instructions to install WolfSSL into Zephyr are down below.

---

## Setup Instructions (nRF Connect for VS Code)
1. Open nRF Connect for Desktop and open Toolchain Manager
   
   ![image](https://github.com/user-attachments/assets/667f3e1f-1209-48f3-abf0-a473978082f7)

3. If not yet installed, install the latest nrf Connect SDK (at time of creation of this read.me it was v2.8.0), install the nRF Connect VS extension and click "Open VS Code".
   
   ![image](https://github.com/user-attachments/assets/289bad61-42c5-4ee3-a051-3782cb0150b9)

4. Download and install WolfSSL crypto library.
   In the VS Explorer look for the `west.yml` file. It's usually in the root directory of the NCS installation (there are several west.yml files).  
   On Windows it's located at `C:\ncs\v2.8.0\nrf\west.yml`.
   
   ![image](https://github.com/user-attachments/assets/bfae4688-ca07-4e21-b2e5-9366b2c5cb70)

   Add this under *remotes*:
   ```yaml
   # WolfSSL Repo
   - name: wolfssl
     url-base: https://github.com/wolfssl
   ```
   and this under *projects*:
   ```yaml
   # WolfSSL master branch
   - name: wolfssl
     path: modules/crypto/wolfssl
     revision: master
     remote: wolfssl
    ```
5. Now save the west.yml file and in the Toolchain manager click update SDK and it will download wolfssl. Alternatively, run `west update` from a nRF Connect terminal window
   
      ![image](https://github.com/user-attachments/assets/0da0ce55-8733-4ffa-9537-78676742c32e)

6. Clone this repository directly into to your VS code environment or to your chosen directory
7. Import it if necessary into visual studio code by clicking file/open_folder/

8. Select the VS nRF Extension and click `Add build configuration` and select as board target `nrf9160dk/nrf9160/ns`
   
   ![WhatsApp Bild 2024-12-05 um 01 02 48_49d84875](https://github.com/user-attachments/assets/0b5c3d51-0478-44a4-98ac-7df08fbffd5d)

9. Now scroll down and click the `Build Configuration` button. Now you can browse `main()`, `prj.conf`, `/include/user_settings_custom.h` and other relevant files.
   Make sure to set your server IP address in `main()`.
   Click `Flash` to flash the code onto the board.

   ![image](https://github.com/user-attachments/assets/89f4f63a-131c-4aa1-be03-2eed50bb60fb)

10. The board will start executing code and will send a DTLS Client Hello to the server. You can open the nRF Connect Serial Terminal to see debug logs of the board.

   ![image](https://github.com/user-attachments/assets/a071627b-ca02-4fb6-9074-c1ea7cff1c26)

   ![image](https://github.com/user-attachments/assets/62ced6ae-8c4c-4f0e-90c3-d92835128914)

