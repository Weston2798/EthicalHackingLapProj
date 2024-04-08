import nmap
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
connection = UnixSocketConnection()
transform = EtreeTransform()


nm = nmap.PortScanner()
host = '10.0.2.4'
nm.scan(host, arguments='-p 1-65535')


print (nm.all_hosts())
with open("PortScan.txt",'a') as f:
    for proto in nm[host].all_protocols():
        print('----------', file=f)
        print('Protocol : %s' % proto, file=f)
        lport = nm[host][proto].keys()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']), file=f)

with Gmp(connection=connection, transform=transform) as gmp:
    gmp.authenticate('username', 'password')
    target = host
    task_id = gmp.create_task(name='Metasploite_Scan', target=target)
    gmp.start_task(task_id)
    gmp.wait_task(task_id)
    results = gmp.get_results(task_id)
    with open("VulnerabilityScan.txt",'a') as f:
        print(results, file=f)