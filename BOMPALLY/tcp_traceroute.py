import argparse
import logger
import datetime
import threading
from socket import *
from scapy.layers.inet import *


tcp_packets = []
dict_lock = threading.Lock()
dict_of_sequences= {}
reach = 0
probe_limit = 3

def probe_target_hop(target_ip, dest_port, ttl, port, seq):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    syn_packet = IP(dst=target_ip, ttl=ttl) / TCP(dport=dest_port, sport=port, flags='S', seq=seq)

    with dict_lock:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        s.sendto(bytes(syn_packet), (target_ip, dest_port))
        dict_of_sequences[seq] = {"start_time": datetime.datetime.today()}

    thread1 = threading.Thread(target=recieve_ICMP_response, args=(ttl,))
    thread2 = threading.Thread(target=recieve_TCP_response, args=(ttl, port, target_ip))

    thread1.start(), thread2.start()
    capture_ip_packets()


def capture_ip_packets():
    try:
        sockt = socket.socket(socket.AF_INET , socket.SOCK_RAW  , socket.IPPROTO_IP)
        data,address = sockt.recvfrom(1024)
        address_data.append((data , address))
        print(IP(data).display())
        sockt.settimeout(0.275)
        while(True):
            data,address = sockt.recvfrom(1024)
            address_data.append((data , address))
            print(IP(data).display())
    except :
        err =1

def recieve_ICMP_response(ttl):
    try:
        sockt = socket.socket(socket.AF_INET , socket.SOCK_RAW  , socket.IPPROTO_ICMP)
        sockt.setsockopt(socket.IPPROTO_IP , socket.IP_TTL , ttl) 
        sockt.settimeout(0.275)
        while(reach != 1):
            data , address = sockt.recvfrom(1024)
            ip = IP(data)
            icmp = ip[ICMP]
            if( icmp.type == 11 and icmp.code == 0):
                tcp = ip["TCP in ICMP"]
                ip_in_icmp = ip["IP in ICMP"]
                dict_of_sequences.get(tcp.seq)["end_time"] = datetime.datetime.today()
                dict_of_sequences.get(tcp.seq)["dst"] = address[0]
        sockt.close()
        return data
    except:
        err = 1

def recieve_TCP_response(ttl, port , target_ip):
    try:
        sockt = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket.IPPROTO_TCP )
        sockt.setsockopt(socket.IPPROTO_IP ,socket.IP_TTL , ttl)
        sockt.bind(('',port))
        data , address = sockt.recvfrom(1024)
        while(address[0] != target_ip):
            data , address = sockt.recvfrom(1024)
            logger.info(address)
        global reach
        reach = 1
        ip = IP(data)
        tcp = ip[TCP]
        if( tcp.flags == "SA"):
            dict_of_sequences[tcp.ack]["end_time"] = datetime.datetime.today()
            dict_of_sequences[tcp.ack]["dst"] = address[0]
            dict_of_sequences[tcp.ack]["ack"] = True
            tcp_packets.append([ttl,data,address])
        sockt.close()
    except:
        err =1

def call_traceroute(target , target_ip , max_hops , target_port):
    threads = []
    port = 80
    seq = 0
    for i in range(1, max_hops+1):
        for j in range(probe_limit):
            threads.append(threading.Thread(target = probe_target_hop , args = (target_ip , target_port , i , port , seq)))
            dict_of_sequences[seq] = {}
            seq += 1
            port += 50
    for i in range(len(threads)):
        threads[i].start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser( )
    parser.add_argument("-m" , "--MAX_HOPS" ,default = 30, type = int ,help = 'Max hops to probe (default = 30)')
    parser.add_argument("-p" , "--DST_PORT" ,default = 80, type = int , help = "TCP destination port (default = 80)")
    parser.add_argument("-t" , "--TARGET"   , help = "Target domain or IP" , required = True)
    arguments = parser.parse_args()

    target_ip = socket.gethostbyname(arguments.TARGET)
    max_hops = arguments.MAX_HOPS
    target_port = arguments.DST_PORT
    target = arguments.TARGET
    call_traceroute(target , target_ip , max_hops , target_port)
    k = dict_of_sequences.keys()
    success = False
    print("traceroute to "+str(target) +" ("+str(target_ip) +"), "+str(max_hops)+" hops max, TCP SYN to port "+str(target_port))
    for i in range(divmod(len(k), probe_limit)[0]):
        hop_dict = {}
        for j in range(probe_limit):
            try:
                host,_,_ = socket.gethostbyaddr(dict_of_sequences[i*probe_limit+j]["dst"])
            except:
                host = None if "dst" not in dict_of_sequences[i*probe_limit+j] else dict_of_sequences[i*probe_limit+j]["dst"]

            if( "dst" in dict_of_sequences[i*probe_limit+j]):
                key = host+" "+ f"({dict_of_sequences[i*probe_limit+j]['dst']})"
                if( hop_dict.get(key) == None):
                    hop_dict[key] = []
                if( "start_time" in dict_of_sequences[i*probe_limit+j] and "end_time" in dict_of_sequences[i*probe_limit+j]):
                    hop_str = (dict_of_sequences[i*probe_limit+j]["end_time"] - dict_of_sequences[i*probe_limit+j]["start_time"]).microseconds
                    hop_dict[key].append(str(hop_str/1000)+" "+"ms")
                else:
                    if( hop_dict.get("*") == None):
                        hop_dict["*"] = []
                    hop_dict["*"].append("*")
                if( "ack"  in dict_of_sequences[i*probe_limit+j] ):
                    success = True
            else:
                if( hop_dict.get("*") == None):
                    hop_dict["*"] = []
                hop_dict["*"].append("*")
        line = ""
        for key in  hop_dict.keys():
            if( key != "*"):
                line = line + key+ " "
                
            for item in hop_dict[key]:
                line = line + item +" "
        print(i+1," "+line)
        if(success):
            break
