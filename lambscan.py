import ipaddress
import boto3
import json
import threading
import argparse
import socket

class Scanner:
    def __init__(self, role_arn="", worker_name="lambscan", worker_max=1, thread_max=1):
        self.role_arn = role_arn
        self.lambda_client = boto3.client('lambda')

        self.worker_count = 0
        self.worker_name = worker_name
        self.worker_max = int(worker_max)
        self.worker_current = 0 # Keep track of which Lambda worker was the last used

        self.thread_max = int(thread_max)

        self.targets = []
        self.ports = []
    
        self.results = []

    def is_ip(self, address):
        try:
            ipaddress.ip_address(address)
        except:
            return False
        return True

    def is_network(self, network):
        try:
            ipaddress.ip_network(network)
        except:
            return False
        return True

    def add_target(self, host):
        # Convert hostnames to IP
        target = socket.gethostbyname(host)
        
        if self.is_ip(target):
            self.targets.append(target)
            return True

        if self.is_network(target):
            for host in ipaddress.ip_network(target).hosts():
                self.targets.append(str(host))
            return True

        return False
        
    def add_targets_from_file(self, filename):
        try:
            f = open(filename, 'r')
            for line in f:
                line = line.strip()
                if not self.add_target(line):
                    print("ERROR: Could not add target: " + str(line))
        except:
            return False
        return True

    def add_port(self, port):
        self.ports.append(Port("TCP", int(port)))

    # Add multiple ports from dict of ports
    # Ports can be a single port, or a range like 80-90
    def add_ports(self, ports):
        for port in ports:
            p = str(port)
            
            # Break up port range into individual ports
            if "-" in p:
                # Get start and end ports
                start = int(p.split("-")[0])
                end = int(p.split("-")[1]) + 1

                for i in range(start, end):
                    self.add_port(i)
            # Otherwise, convert string value to int
            else:
                self.add_port(port)

    def add_ports_from_string(self, ports):
        port_list = ports.split(',')
        self.add_ports(port_list)

    # Add workers to Lambda
    def lambda_create_workers(self):
        for i in range(self.worker_max):
            fn_name = self.worker_name + "_" + str(i)
            self.lambda_client.create_function(
                FunctionName=fn_name,
                Runtime='python3.8',
                Role=self.role_arn,
                Handler=f"{self.worker_name}.lambda_handler",
                Code={'ZipFile': open(f"{self.worker_name}.zip", 'rb').read(), },
                Timeout=3
            )

        self.worker_count = self.count_lambda_workers()

    # Get number of worker functions in Lambda
    def count_lambda_workers(self):
        function_count = 0

        for function in self.lambda_client.list_functions()['Functions']:
            prefix = self.worker_name + "_"
            if prefix in function['FunctionName']:
                function_count = function_count + 1

        return function_count

    # Delete all workers from Lambda
    def lambda_cleanup(self):
        try:
            # Get number of matching functions
            function_count = self.count_lambda_workers()
            
            # Delete functions
            if function_count > 0:
                # Find all functions with FUNCTION_NAME_ prefix
                for function in self.lambda_client.list_functions()['Functions']:
                    prefix = self.worker_name + "_"
                    if prefix in function['FunctionName']:
                        # delete
                        self.lambda_client.delete_function(FunctionName=function['FunctionName'])

            # Update list now
            self.worker_count = self.count_lambda_workers()
            
            return 0
        except:
            return 1

    # Keeping track of which worker is in use
    def next_worker(self):
        self.worker_current = self.worker_current + 1
        if self.worker_current == self.worker_max:
            self.worker_current = 0

    # Scan a single port
    def scan_port(self, target, p):
        # Invoke Lambda function to actually check port
        response = self.lambda_client.invoke(
            FunctionName=f'{self.worker_name}_{self.worker_current}',
            InvocationType='RequestResponse',
            Payload=json.dumps(dict({'host': target, 'proto': p.get_proto(), 'port': p.get_port()}))
        )

        # Get response
        result = json.loads(response['Payload'].read().decode('utf-8'))
        
        # Parse result
        if 'errorMessage' in result:
            status = False          # Sometimes Lambda will time out trying to connect to a closed port
        elif 'body' in result:
            status = result['body'] # True or False
        else:
            status = None           # Something went wrong

        self.results.append(Result(target, p, status))
        self.next_worker()

    def init_scan(self):
        port_count = len(self.ports)

        # loop through all targets
        for target in self.targets:
            port_counter = 0
            # Need to loop until all ports have been scanned
            while port_counter < port_count: 
                port = self.ports[port_counter]

                # Make sure we haven't filled all our threads yet
                if threading.active_count() <= self.thread_max:
                    # Launch daemon thread to scan a single port
                    t = threading.Thread(target=self.scan_port, args=(target, port), daemon=True)
                    t.start()

                    # Increment port_counter only if we started a new thread
                    port_counter = port_counter + 1

    def get_results(self):
        return self.results

class Port:
    def __init__(self, proto, port):
        self.proto = proto
        self.port = port

    def get_port(self):
        return self.port

    def get_proto(self):
        return self.proto

    def update_port(self, proto, port):
        self.proto = proto
        self.port = port

class Result:
    def __init__(self, target, port, status):
        self.target = target
        self.proto = port.get_proto()
        self.port = port.get_port()
        self.status = self.convert_status(status)

    def convert_status(self, status):
        if status == True or str(status).lower() == "open":
            return "open"
        elif status == False or str(status).lower() == "closed":
            return "closed"
        return None

    def get_result(self):
        return self.target, self.proto, self.port, self.status

    def update_result(self, target, port, status):
        self.target = target
        self.proto = port.get_proto()
        self.port = port.get_port()
        self.status = convert_status(status)

##########################################
# Parse arguments
##########################################
def parse_args(parser):
    parser.add_argument('ports', nargs='?', help='Ports to scan. Example:80,81,1000-2000')
    parser.add_argument('role', nargs='?', help='AWS IAM role ARN for lambda functions to use')
    parser.add_argument('--target', nargs='?', dest='target', help='IP address or CIDR range')
    parser.add_argument('--target-file', nargs='?', dest='target_file', help='File with one IP address or CIDR per line')
    parser.add_argument('--workers', default=1, dest='max_workers', help='Number of Lambda workers to create')
    parser.add_argument('--threads', default=1, dest='max_threads', help='Max number of threads for port scanning')
    parser.add_argument('--clean', default=False, action='store_true', help='Do not scan. Delete all Lambda functions matching ^lambscan_. Use if something goes wrong.')

    args = parser.parse_args()

    return args

##############################################
# Main program execution
##############################################
if __name__ == "__main__":
    # Defaults
    fn_name = "lambscan"

    # Parse arguments
    parser = argparse.ArgumentParser(description='LambScan by Rick Osgood')
    args = parse_args(parser)

    # Initialize scanner
    scanner = Scanner(args.role, fn_name, args.max_workers, args.max_threads)

    # Check if user wants to clean out old functions
    if args.clean:
        try:
            scanner.lambda_cleanup()
        except Exception as e:
            print("ERROR: Could not delete LambScan functions!\nException: " + str(e))
            exit(1)
        exit(0)

        # Make sure required arguments are set
    if not (args.target or args.target_file) or not args.ports or not args.role:
        parser.print_help()
        exit(1)

    if args.target and args.target_file:
        print("ERROR: Specify a target or a target file, not both.")
        exit()

    scanner.add_ports_from_string(args.ports)
    
    if args.target_file:
        scanner.add_targets_from_file(args.target_file)
    if args.target:
        scanner.add_target(args.target)

    print("[*] Creating Lambda workers in AWS...")
    scanner.lambda_create_workers()

    print("[*] Scanning ports...")
    # Initiate port scan
    scanner.init_scan()

    # Wait for threads to end
    main_thread = threading.main_thread()
    for t in threading.enumerate():
        if t is main_thread:
            continue
        t.join()

    # Print results
    for result in scanner.get_results():
        print(f"{result.target}, {result.proto}, {result.port}/{result.status}")

    # Delete LambScan worker functions
    print("[*] Deleting Lambda workers from AWS...")
    scanner.lambda_cleanup()

    # Validate worker functions were deleted
    print(f"[*] Found {scanner.worker_count} LambScan functions left in AWS account")
