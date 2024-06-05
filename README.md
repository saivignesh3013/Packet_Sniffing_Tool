# Packet Sniffing Tool

**Author: Erramsetti Sai Vignesh**

**Unveil the secrets of network traffic with this Python tool. It leverages the Scapy library to capture and analyze packets flowing through your network, but remember to use it responsibly.**

**Important Note:** Packet sniffing can be a powerful tool for network monitoring and analysis. However, it's crucial to use it ethically and with proper authorization. Using a packet sniffer on a network without permission is a violation of privacy and may be illegal.

**Features:**

* **Packet Capture:** Captures network packets flowing through the interface you specify.
* **Protocol Identification:** Identifies the protocol used in each packet (TCP, UDP, ICMP, etc.).
* **IP Address Tracking:** Tracks source and destination IP addresses for network traffic.
* **Payload Analysis (Limited):** Displays the payload of captured packets for basic analysis (may not be human-readable for all protocols).
* **Logging:** Logs captured packet information (source/destination IP, protocol, payload) to a file for further analysis.

**How to Use:**

1. **Save the Script:** Save the script as `packet_sniffer.py` (or your preferred name).
2. **Run the Script:** Execute the script from the command line using `python packet_sniffer.py`.
3. **Start Sniffing:** The program will start capturing packets.
4. **Stop Sniffing:** Press `Ctrl+C` to stop the packet sniffing process.
5. **Captured Packets:** The captured packet information will be logged to the file `packet_log.txt`.

**Ethical Considerations:**

* **Consent:** Always obtain explicit permission before using a packet sniffer on a network.
* **Security:** Be aware of the potential security risks associated with packet sniffing, such as exposing sensitive information.
* **Legal Issues:** Using a packet sniffer without authorization may be illegal in certain jurisdictions.

**Disclaimer:**

This tool is intended for educational purposes or network troubleshooting with proper authorization. Using it for malicious purposes is strictly prohibited.

**Additional Notes:**

* The provided code offers a basic level of payload analysis. Depending on the protocol, the payload might not be human-readable.
* Consider exploring advanced packet sniffing techniques and tools for more comprehensive network analysis.

**Remember:** Use packet sniffing ethically, responsibly, and with proper authorization.
