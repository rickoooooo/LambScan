import boto3
import argparse
import json
import threading

# Constants
FUNCTION_NAME = "lambscan" # Prefix for lambda function names

##########################################
# Parse arguments
##########################################
def parse_args():
    parser = argparse.ArgumentParser(description='LambScan by Rick Osgood')
    parser.add_argument('target', nargs='?', help='Target to scan. Example: 8.8.8.8')
    parser.add_argument('ports', nargs='?', help='Ports to scan. Example:80,81,1000-2000')
    parser.add_argument('role', nargs='?', help='AWS IAM role ARN for lambda functions to use')
    parser.add_argument('--workers', dest='worker_num', help='Number of Lambda workers to create')
    parser.add_argument('--threads', dest='max_threads', help='Max number of threads for port scanning')
    parser.add_argument('--clean', default=False, action='store_true', help='Do not scan. Delete all Lambda functions matching ^lambscan_. Use if something goes wrong.')

    args = parser.parse_args()

    # Check if user wants to clean out old functions
    if args.clean:
        try:
            lambda_clean()
        except Exception as e:
            print("ERROR: Could not delete LambScan functions!\nException: " + str(e))
            exit(2)
        exit(0)

    # Make sure required arguments are set
    if not args.target or not args.ports or not args.role:
        parser.print_help()
        exit(2)

    scan_params = {}
    scan_params['target'] = args.target
    scan_params['ports'] = str(args.ports).split(",")
    scan_params['proto'] = 'tcp'
    scan_params['max_threads'] = int(args.max_threads)
    scan_params['role'] = args.role

    # Defaults
    scan_params['worker_num']= 1
    scan_params['max_threads'] = 1
    if args.worker_num:
        scan_params['worker_num'] = int(args.worker_num)
    if args.max_threads:
        scan_params['max_threads'] = int(args.max_threads)

    return scan_params

#########################################################
# Remove all lambda functions matching lambscan prefix
# Used in case something went wrong in a previous run
#########################################################
def lambda_clean():
    try:
        print("[*] Cleaning up lambda functions...")
        # Setup lambda client
        lambda_client = boto3.client('lambda')

        # Get number of matching functions
        function_count = lambda_function_count(lambda_client, FUNCTION_NAME)
        print(f"[*] Found {function_count} matching LambScan functions")

        print(f"[*] Deleting LambScan functions...")
        if function_count > 0:
            # Find all functions with FUNCTION_NAME_ prefix
            for function in lambda_client.list_functions()['Functions']:
                prefix = FUNCTION_NAME + "_"
                if prefix in function['FunctionName']:
                    # delete
                    lambda_client.delete_function(FunctionName=function['FunctionName'])

            # Validate worker functions were deleted
            function_count = str(lambda_function_count(lambda_client, FUNCTION_NAME))
            print(f"[*] Found {function_count} LambScan functions left in AWS account after cleanup")
    except Exception as e:
        print("ERROR: Something went wrong cleanup up Lambda functions!\nException: " + str(e))
        exit(2)

#####################################
# Create lambda workers
#####################################
def lambda_create_workers(lambda_client, worker_num, fn_name):
    print("[*] Creating Lambda worker functions...")
    for i in range(worker_num):
        fn_fullname = fn_name + "_" + str(i)
        lambda_client.create_function(
            FunctionName=fn_fullname,
            Runtime='python3.8',
            Role=fn_role,
            Handler=f"{fn_name}.lambda_handler",
            Code={'ZipFile': open(f"{fn_name}.zip", 'rb').read(), },
        )

#####################################
# Scan single port
#####################################
def scan_port(lambda_client, event, worker_counter):
    # Invoke Lambda function to actually check port
    response = lambda_client.invoke(
        FunctionName=f'lambscan_{worker_counter}',
        InvocationType='RequestResponse',
        Payload=json.dumps(event),
    )

    result = json.loads(response['Payload'].read().decode('utf-8'))

    # True or False
    if result['body'] == True:
        print(f"{event['host']}, {event['port']}/open")
    else:
        print(f"{event['host']}, {event['port']}/closed")

######################################
# Loop through ports to scan
######################################
def scan_ports(lambda_client, scan_params):
    target = scan_params['target']
    port_list = scan_params['ports']
    proto = scan_params['proto']
    max_threads = scan_params['max_threads']
    worker_num = scan_params['worker_num']
    ports = []

    print("[*] Scanning ports...")
    for entry in port_list:
        e = str(entry)
        # Break up port range into individual ports
        if "-" in e:
            # Get start and end ports
            start = int(e.split("-")[0])
            end = int(e.split("-")[1]) + 1

            for i in range(start, end):
                ports.append(i)
        # Otherwise, convert string value to int
        else:
            ports.append(int(entry))

    # Do some scanning
    # Loop through all ports

    worker_counter = 0 # For keeping track of workers

    port_num = len(ports)
    port_counter = 0
    # Need to loop until all ports have been scanned
    while port_counter < port_num: 
        port = ports[port_counter]
        event = dict({'host': target, 'proto': 'tcp', 'port': port})

        # Make sure we haven't filled all our threads yet
        if threading.active_count() <= max_threads:
            # Make sure the next port to be scanned uses the next worker in line
            if worker_counter == worker_num:
                worker_counter = 0

            # Launch daemon thread to scan a single port?
            t = threading.Thread(target=scan_port, args=(lambda_client, event, worker_counter), daemon=True)
            t.start()

            # Increment to the next Lambda worker
            worker_counter = worker_counter + 1

            # Increment port_counter only if we started a new thread
            port_counter = port_counter + 1

##############################################
# Delete Lambda functions
##############################################
def lambda_destroy_workers(lambda_client, fn_name, worker_num):
    # Destroy lambda workers
    print("[*] Deleting Lambda worker functions...")
    for i in range(worker_num):
        fn_fullname = fn_name + "_" + str(i)
        lambda_client.delete_function(
            FunctionName=fn_fullname
        )

########################################################
# Get number of lambda functions matching fn_name
########################################################
def lambda_function_count(lambda_client, fn_name):
    function_count = 0

    for function in lambda_client.list_functions()['Functions']:
        prefix = fn_name + "_"
        if prefix in function['FunctionName']:
            function_count = function_count + 1

    return function_count

##############################################
# Main program execution
##############################################
if __name__ == "__main__":
    # Defaults
    fn_name = FUNCTION_NAME

    # Setup lambda client
    lambda_client = boto3.client('lambda')

    # Parse arguments
    scan_params = parse_args()

    # set execution role
    fn_role = scan_params['role']

    # Create Lambda worker functions
    try:
        lambda_create_workers(lambda_client, scan_params['worker_num'], fn_name)
    except Exception as e:
        print("ERROR: Could not create worker functions!\nException: " + str(e))
        lambda_clean()
        exit(2)

    # Validate they were all created
    function_count = str(lambda_function_count(lambda_client, fn_name))
    print(f"[*] Created {function_count} LambScan functions")

    # Initiate port scan
    try:
        scan_ports(lambda_client, scan_params)
    except Exception as e:
        print("ERROR: Something went wrong during port scanning!\nException: " + str(e))
        lambda_clean()
        exit(2)

    # Wait for threads to end
    main_thread = threading.main_thread()
    for t in threading.enumerate():
        if t is main_thread:
            continue
        t.join()

    # Delete LambScan worker functions
    lambda_destroy_workers(lambda_client, fn_name, scan_params['worker_num'])

    # Validate worker functions were deleted
    function_count = str(lambda_function_count(lambda_client, fn_name))
    print(f"[*] Found {function_count} LambScan functions left in AWS account")
