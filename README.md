# ICS_Cyber_Range

## Overview

**ICS_Cyber_Range** is a cyber range designed to simulate and test a secure network infrastructure using public key cryptography. The goal is to secure Modbus communication, a widely used protocol in industrial control systems (ICS). This project uses OpenPLC to simulate a Programmable Logic Controller (PLC) and provides a controlled environment to experiment with securing ICS protocols.

### What is a Cyber Range?

A cyber range is a virtual environment that allows researchers, developers, and security professionals to safely simulate, test, and train in cybersecurity. It provides a realistic, isolated setup for experimenting with network configurations, attack simulations, and security defenses without impacting real-world systems.

### Network Components

- **Central Server**: Generates certificates and distributes them across the network.
- **HMI (Human-Machine Interface)**: The interface for monitoring and controlling the PLC.
- **PLC (Programmable Logic Controller)**: Simulated using OpenPLC to control industrial processes.
- **Proxies**: Each device in the network (HMI and PLC) has its own proxy to manage secure communication.
- **Attacker**: A simulated attacker to test the security of the system.

## Getting Started

Follow the steps below to set up and run the ICS_Cyber_Range.

### 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/ICS_Cyber_Range.git
cd ICS_Cyber_Range
```

### 2. Build and Start the Environment

Use Docker Compose to build and start the entire environment:
```bash
docker compose up --build
```

### 3. Activate OpenPLC

To activate the OpenPLC simulator:

- Connect to the OpenPLC interface by navigating to http://localhost:8080 in your web browser.
- Log in with the credentials:
    - Username: openplc
    - Password: openplc
- Load the Hello.st program and start it.

Next, access the bash of the OpenPLC container and modify the default gateway to route traffic through the PLC proxy:
```bash
docker exec -it plc1 bash
ip route del default
ip route add default via 172.29.0.4
```

### 4. Start the proxies
Once the environment is up, access the bash of proxy1 and proxy2 to generate the necessary certificates:
```bash
# For Proxy 1
docker exec -it proxy1 bash
cd scripts
python3 cert.py

# For Proxy 2
docker exec -it proxy2 bash
cd scripts
python3 cert.py
```

After generating the certificates, start the proxy services on both proxy1 and proxy2:
```bash
# On Proxy 1
python3 proxy.py

# On Proxy 2
python3 proxy.py
```

### 5. Test communication with HMI
Access the bash of the HMI container:

```bash
docker exec -it hmi bash
```

Start the testing script:
```bash
cd scripts
python3 client.py
```

## Acknowledgements
- [OpenPLC] (https://github.com/thiagoralves/OpenPLC_v3)
- [Dilithium-py] (https://github.com/GiacomoPope/dilithium-py)
- [Kyber-py] (https://github.com/GiacomoPope/kyber-py)