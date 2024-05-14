# OT_Testbed_simulator

To run the simulator, execute the following command on the main folder
```
docker compose up
```

Connect through the browser to localhost:8080 to access to the OpelPLC Runtime WebApp. Username and password are openplc. Start the plc with the blue button on the left.
If the connection between the HMI and the PLC doesn't work, try these commands:
```
sudo docker exec -ti plc1 bash

ip route del default
ip route add default via 172.29.0.3
```
