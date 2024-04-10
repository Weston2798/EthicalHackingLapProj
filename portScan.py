import nmap



def portSanner(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-p 1-65535')

    with open("PortScan.txt",'a') as f:
        for proto in nm[host].all_protocols():
            print('----------', file=f)
            print('Protocol : %s' % proto, file=f)
            lport = nm[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']), file=f)