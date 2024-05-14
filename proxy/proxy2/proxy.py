from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
from netfilterqueue import NetfilterQueue
import crypto

iptablesr1 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"
os.system(iptablesr1)
os.system(iptablesr2)


#Dizionario per salvare le chiavi simmetriche (ip: chiave)
keys = dict()
  
'''
class ModbusTCP(Packet):
    name = "ModbusTCP"
    fields_desc = [ ShortField("transaction_id", 0),
                    ShortField("protocol_id", 0),
                    ShortField("length", None),
                    ByteField("unit_id", 0) 
                ]
class Modbus(Packet):
    name = "Modbus"
    fields_desc = [ ByteField("function_code", 0),
                    ShortField("reference_number", 0),
                    ShortField("bit_count", 0),
                    ByteField("byte_count", 0),
                    ByteField("data", 0)
                ]
'''
def main():
    def packet_handler(packet):
        is_verified = True
        print("test")
        pkt = IP(packet.get_payload())
        pkt.show()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        print(f"IP packet: {src_ip} -> {dst_ip}")
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print(f"TCP packet: {src_port} -> {dst_port}")
            #Se il pacchetto è indirizzato al hmi
            if pkt.haslayer(Raw) and pkt[IP].dst == "172.27.0.5":
                raw_data = bytes(pkt[Raw].load)
                #OLD WAY: decrypted_data = decrypt_aes(raw_data)
                decrypted_data, is_verified = crypto.decrypt_and_verify_message(raw_data, keys[src_ip], src_ip + "_public_key.pem")
                if is_verified:
                    pkt[Raw].load = decrypted_data
                    print("Raw data decriptati")
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    pkt.show2()
                else:
                    print("Firma non verificata")
            #Se il pacchetto è indirizzato al plc
            elif pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                #OLD WAY: encrypted_data = encrypt_aes(raw_data)
                encrypted_data = crypto.encrypt_and_sign_message(raw_data,keys[dst_ip],src_ip + "_private_key.pem")
                pkt[Raw].load = encrypted_data
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                pkt.show2()
                #packet.set_payload(bytes(pkt))
                print("Raw data criptati")
            elif pkt[TCP].flags & 2 and pkt[IP].dst != "172.27.0.5":
                new_key = get_random_bytes(16)
                encrypted_key = crypto.encrypt_and_sign_symmetric_key(new_key, dst_ip + "_public_key.pem", src_ip + "_private_key.pem")
                keys[dst_ip] = new_key
                pkt[TCP].add_payload(encrypted_key)
                del pkt[IP].chksum
                del pkt[TCP].chksum
                del pkt[IP].len
                pkt.show2()
        packet.drop()
        if is_verified:
            send(pkt)
    
    
    #bind_layers(TCP, ModbusTCP, dport=502)
    #bind_layers(ModbusTCP, Modbus)    
    print("Starting...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, packet_handler)
    try:
        print("Running...")
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()
        os.system("iptables -D FORWARD -i eth1 -j NFQUEUE --queue-num 0")
        os.system("iptables -D FORWARD -i eth0 -j NFQUEUE --queue-num 0")
        os.system('iptables -X')
        
    
    #sniff(iface="eth0", prn=packet_from_inside_handler, store=0)
    #sniff(iface="eth1", prn=packet_from_outside_handler, store=0)

if __name__ == "__main__":
    main()