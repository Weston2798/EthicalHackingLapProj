import nmap

# Create a PortScanner object
nm = nmap.PortScanner()

nm.scan('192.168.50.192', arguments='-p 1-65535')
host = '192.168.50.192'

print (nm.all_hosts())
with open("output.txt",'a') as f:
    for proto in nm[host].all_protocols():
        print('----------', file=f)
        print('Protocol : %s' % proto, file=f)
        lport = nm[host][proto].keys()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']), file=f)

