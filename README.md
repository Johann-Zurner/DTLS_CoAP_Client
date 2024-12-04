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
2. Install the latest nrf Connect SDK (at time of creation of this read.me it was v2.8.0) and click Open VS Code
![image](https://github.com/user-attachments/assets/6d8ce488-6fc5-4820-a893-cd56e80477cd)
3. 


### 1. Clone the Project
1. Open **Visual Studio Code** with the **nRF Connect extension** installed.
2. Use the **nRF Connect Welcome Page** to open a new terminal.
3. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/CoAP_Client_DTLS.git
   cd CoAP_Client_DTLS
