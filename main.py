import nmap
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
connection = UnixSocketConnection()
transform = EtreeTransform()


nm = nmap.PortScanner()
host = '10.0.2.4'
nm.scan(host, arguments='-p 1-2000')


print (nm.all_hosts())
with open("PortScan.txt",'a') as f:
    for proto in nm[host].all_protocols():
        print('----------', file=f)
        print('Protocol : %s' % proto, file=f)
        lport = nm[host][proto].keys()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']), file=f)

with Gmp(connection=connection, transform=transform) as gmp:
    gmp.authenticate('admin2', '31eba0a4-eb15-4118-8ca4-ed06e13a8329')
    #task_id = gmp.create_task(name='Metasploite_Scan1', target_id='23b0a7bd-6620-4c32-bac0-c1598af2a014',config_id='daba56c8-73ec-11df-a475-002264764cea', scanner_id='08b69003-5fc2-4037-a479-93b440211c73')
    gmp.start_task(task_id='4f65b771-b598-4d72-8077-748040ccc08d')
    gmp.wait_task(task_id='4f65b771-b598-4d72-8077-748040ccc08d')
    results = gmp.get_results(task_id='4f65b771-b598-4d72-8077-748040ccc08d')
    with open("VulnerabilityScan.txt",'a') as f:
        print(results, file=f)