import nmap
nm = nmap.PortScanner()

host  = '127.0.0.1'
host = r'192.168.50.192'
#nm.scan(host, '1-3000')
scan_result = nm.scan('192.168.50.192', arguments='-p 1-65535')
with open("output.txt",'a') as f:
    print(nm.all_hosts(), file=f)
    #print(nm[host].all_protocols(), file=f)


'''
with open("output.txt",'a') as f:
    for proto in nm[host].all_protocols():
        print('----------', file=f)
        print('Protocol : %s' % proto, file=f)
        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']), file=f)
'''