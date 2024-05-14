from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from netfilterqueue import NetfilterQueue
import crypto

iptablesr1 = "iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A FORWARD -i eth0 -j NFQUEUE --queue-num 0"
os.system(iptablesr1)
os.system(iptablesr2)

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

def encrypt_aes(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def decrypt_aes(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size)

def main():
    def packet_handler(packet):
        is_verified = True
        pkt = IP(packet.get_payload())
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        print(f"IP packet: {src_ip} -> {dst_ip}")
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print(f"TCP packet: {src_port} -> {dst_port}")
            #Se il pacchetto è indirizzato al plc
            if pkt.haslayer(Raw) and pkt[IP].dst == "172.29.0.2":
                raw_data = bytes(pkt[Raw].load)
                if pkt[TCP].flags & 2:
                    new_key, is_verified = crypto.decrypt_and_verify_symmetric_key(raw_data, dst_ip + "_private_key.pem", src_ip + "_public_key.pem")   
                    if is_verified:
                        keys[src_ip] = new_key
                        print("Chiave simmetrica aggiornata")
                else:        
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
            #Se il pacchetto è indirizzato al client
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
        packet.drop()
        #pkt.show()
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