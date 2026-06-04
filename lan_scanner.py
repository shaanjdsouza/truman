from argparse import ArgumentParser
from scapy.all import ARP,Ether,srp

parser = ArgumentParser(
    prog = 'LAN Scanner',
    description = 'Network scanner that uses ARP requests'
)

#help menu
parser.add_argument('-t',"--target", help = "Use the flag -t to specify your target. Must be in CIDR notation (e.g : 192.168.1.0/24)", required = True)

#parsing cl arguments
args = parser.parse_args()

#change target to wtv ip address u want to scan
target_ip = args.target

#create arp packet
arp = ARP(pdst = target_ip)

#create ether broadcast package
ether = Ether(dst = 'ff:ff:ff:ff:ff:ff')

#stack ether and arp together into a single packet
packet = ether/arp

result = srp(packet,timeout = 3,verbose = 0)[0]

#list of clients
clients = []

for sent, recieved in result:
    clients.append({'ip' : recieved.psrc, 'mac' : recieved.hwsrc})  #for each response, append ip and mac address to the list of clients

print("Available devices on this network :")
print("IP" + " "*18 + "MAC")

for client in clients:
    print("{:16}  {}".format(client['ip'],client['mac']))