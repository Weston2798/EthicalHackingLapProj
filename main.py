from portScan import portSanner
from vulnarabilityScan import vulnurabilityScanner
from intrusionDetection import start_sniffing
host = "10.0.2.4"
portSanner(host=host)
vulnurabilityScanner()