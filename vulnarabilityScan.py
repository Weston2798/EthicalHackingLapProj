from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
connection = UnixSocketConnection()
transform = EtreeTransform()

def vulnurabilityScanner():
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate('admin2', '31eba0a4-eb15-4118-8ca4-ed06e13a8329')
        gmp.start_task(task_id='4f65b771-b598-4d72-8077-748040ccc08d')
 