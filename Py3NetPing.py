import sys
import time
import re

import requests
import nmap
import ping3
import socket
import geoip
import ipwhois
import geoip2.database
from ipwhois import IPWhois
from scapy.layers.inet import IP, ICMP, sr1, sr, TCP

print("\nSystem Info: \n" + sys.version + "\n" + str(sys.api_version) + "\n" + str(sys.version_info) + "\n")


class NetworkScanner:

    ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535


    def __init__(self):
        print("| --- -- - Welcome To Py3PortPinger - -- --- |")
    def getIP(self):
        while True:
            ip_add_entered = input("\nEnter the target ip >")
            time.sleep(0.5)
            if self.ip_add_pattern.search(ip_add_entered):
                print(f"{ip_add_entered} is a valid ip address")
                return ip_add_entered
    def getPortRange(self):
        starting_port = None
        ending_port = None
        while True:
            try:
                starting_port = int(input("Enter the starting port number to scan (Here-#) >"))
                ending_port = int(input("Enter the ending port number to scan (#-Here) >"))
                if starting_port < self.port_min or ending_port > self.port_max:
                    print("...Invalid Port Number...")
                    continue
            except:
                print("...Invalid Port Number...")
            return (range(starting_port, ending_port + 1))
    def getURL(self):
        urlInput = input("Enter URL >")
        return urlInput
    def perform_scapy_scan(self):

        while True:
            #Menu
            print("\n-- - Scapy Scanner - --")

            #Input Target IP
            target_ip = None
            target_ip = self.getIP()
            if target_ip is None:
                print("...exiting...")
                return

            try:
                icmp_response = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose = 0)
                if icmp_response:
                    print(f"ICMP Ping to {target_ip} successful")
                else:
                    print(f"ICMP Ping to {target_ip} failed...")
                tcp_response = sr1(IP(dst=target_ip)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
                if tcp_response and tcp_response[TCP].flags == "SA":
                    print(f"TCP Port 80 is open on {target_ip}")
                else:
                    print(f"TCP Port 80 is closed or filtered on {target_ip}")

                responses, _ = sr(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
                print("Network Scan Results:")
                for resonse in responses:
                    print(f"IP: {resonse[1][IP].src}, Response: {resonse[1][ICMP].type}")
            except:
                print(f"\nerror could not scan {target_ip}\n")

            userCheck = input("\ntype \"exit\" to return to menu or hit Enter to scan again >")
            if userCheck == "exit":
                return

    def get_target_ip_info(self):
    # Scapy
        # Create an ICMP packet (ping) and send it to the target IP
        target_ip = self.getIP()
        packet = IP(dst=target_ip) / ICMP()
        response = sr1(packet, timeout=2, verbose=0)

        if response:
            print(f"Target IP: {target_ip}")
            print(f"Response IP: {response[IP].src}")
            print("Response:")
            response.show()

    def PingIP(self, ip_addr):
        response_time = ping3.ping(ip_addr, timeout=2)
        if response_time is not None:
            print(f"Ping to {ip_addr} successful. Response Time {response_time} ms")
        else:
            print(f"Ping to {ip_addr} failed...")

    def perform_ping(self):
        #Menu
        print("\n-- - Network Ping - --\ntype \"exit\" to return to menu\n\n")

        while True:
            ip_addr = None
            ip_addr = self.getIP()
            if ip_addr is None:
                print("...exiting...")
                return
            else:
                try:
                    response_time = ping3.ping(ip_addr, timeout=2)
                    if response_time is not None:
                        print(f"Ping to {ip_addr} successful. Response Time {response_time} ms")
                    else:
                        print(f"...Ping to {ip_addr} failed...")
                except:
                    print("...ping failed...")

            userCheck = input("\ntype \"exit\" to return to menu or hit Enter to scan again >")
            if userCheck == "exit":
                return

    # Network Scan - tests if host is up and available ports
    def perform_network_scan(self):

        while True:
            #Menu
            print("\n-- - Network Scanner - --\ntype \"exit\" to return to menu\n\n")

            #Input Target IP
            target_ip = None
            target_ip = self.getIP()
            if target_ip is None:
                print("...exiting...")
                return

            try:
            #Begin Scan
                nm = nmap.PortScanner()

                # Perform a ping scan to check if the host is up

                ping_result = nm.scan(hosts=target_ip, arguments='-sn')
                if target_ip in ping_result['scan']:
                    print(f"Host {target_ip} is up.")
                else:
                    print(f"Host {target_ip} is not responding to pings.")
                    continue

            # Perform a port scan to identify open ports

                port_scan_result = nm.scan(hosts=target_ip, arguments='-p 1-65535')
                open_ports = []
                for port in port_scan_result['scan'][target_ip]['tcp']:
                    if port_scan_result['scan'][target_ip]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)

                if open_ports:
                    print(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
                else:
                    print(f"No open ports found on {target_ip}.")
            except:
                print(f"...error while scanning ports on {target_ip}...")

            userCheck = input("\ntype \"exit\" to return to menu or hit Enter to scan again >")
            if userCheck == "exit":
                return

    #Socket Scanning - target_ip + port
    def scan_port_range(self, target_ip, port_range):
        open_ports = []
        for port in port_range:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    def perform_portrange_scan(self):
        while True:
            target_ip = None
            target_ip = self.getIP()
            if target_ip is None:
                print("...exiting...")
                return

            port_range = None
            '''
            try:
                startport = int(input("Enter the starting port # >"))
            except:
                print("...Invalid...")
                continue
            try:
                endport = int(input("Enter the ending port # >"))
            except:
                print("...Invalid...")
                continue
            

            port_range = range(startport, endport+1)
            '''
            port_range = self.getPortRange()
            print("...scanning...")
            open_ports = self.scan_port_range(target_ip, port_range)

            if open_ports:
                print(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
            else:
                print(f"No open ports found on {target_ip}.")

            userCheck = input("\ntype \"exit\" to return to menu or hit Enter to scan again >")
            if userCheck == "exit":
                return

    #Request - URL
    def perform_url_request(self):
        url = input("Enter URL >")
        try:
            response = requests.get(url)
            response.raise_for_status() # Raise an exception if the request was not successful

            print("Status Code: ", response.status_code)
            print("Headers:")
            for header, value in response.headers.items():
                print(f"{header}: {value}")

            print("\nResponse Content:")
            print(response.text[:300])

            data = response.json() # Parse JSON response content

            if data: #api data
                print("Fetched Data")
                print("Title: ", data["title"])
                print("Body: ", data["body"])
            else:
                print("...Failed to fetch data...")

            return
        except requests.exceptions.RequestException as e:
            print("Error ", e)
            return

    def get_geo_ipinfoio_info(self, target_ip):
        try:
            response = requests.get(f"https://ipinfo.io/{target_ip}/json")
            if response.status_code == 200:
                geolocation_data = response.json()
                print("Geolocation Data:")
                print(f"IP Address: {geolocation_data['ip']}")
                print(f"City: {geolocation_data['city']}")
                print(f"Region: {geolocation_data['region']}")
                print(f"Country: {geolocation_data['country']}")
            else:
                print("Geolocation data not available")

        except requests.exceptions.RequestException as e:
            print("Error fetching geolocation data:", e)
        except:
            print("ipinfo.io fetching failed or not available")

    def get_ip_whois_info(self, target_ip):
        try:
            ipwhois = IPWhois(target_ip)
            whois_data = ipwhois.lookup_rdap()
            print("Whois Data:")
            for key, value in whois_data.items():
                print(f"{key.capitalize()}: {value}")
        except Exception as e:
            print("Error fetching IP whois data:", e)
        except:
            print("ipwhois fetching failed or not available")

    #GeoIP2
    def get_geoip2_database_info(self, target_ip):

        try:
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(target_ip)

            print("Geolocation Data:")
            print(f"IP Address: {target_ip}")
            print(f"City: {response.city.name}")
            print(f"Region: {response.subdivisions.most_specific.name}")
            print(f"Country: {response.country.name}")
            print(f"Subdivisions: {response.subdivisions.most_specific}")
            print(f"Postal ALL: {response.postal}")
            print(f"Location: Latitude {response.location.latitude}, Longitude {response.location.longitude}\n")
            print(f"Location All: {response.location}")

        except Exception as e:
            print("Error fetching geolocation data:", e)

        try:
            reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            response = reader.country(target_ip)

            print("Geolocation Data:")
            print(f"IP Address: {target_ip}")
            print(f"Country: {response.country.name}")
            print(f"Continent: {response.continent.name}")
            print(f"Registered Country: {response.registered_country}")
            print(f"Represented Country: {response.represented_country}")
            print(f"Raw ALL: {response.raw}\n")
            print(f"ISP ALL: {response.traits}")

        except Exception as e:
            print("Error fetching geolocation data:", e)

    def perform_ip_geo_scan(self):
        try:
            target_ip = self.getIP()
            print("\n")
            self.get_geoip2_database_info(target_ip)
            self.get_ip_whois_info(target_ip)
            self.get_geo_ipinfoio_info(target_ip)
        except:
            print("error obtaining ip's geolocation")



def Menu(MyNetworkScanner: NetworkScanner):

    while True:
        print("\n-- - Menu - --\n\n-1.Exit Menu\n1.Get Target IP Packet Info(IMCP)\n2.Ping IP\n3.Network Port Scan\n4.Scapy ICMP/TCP Scan\n5.Socket Scanner - Port Range\n6. Request Data from URL\n7. Get Geolocation of target ip + details\n")
        userInput = input("Enter value >")

        try:
            choice = int(userInput)
        except:
            print("\nunknown command...enter an menu option 1-5")
            continue
        if choice == -1:
            print("...exiting NetworkScanner...")
            break
        if choice == 1:
            MyNetworkScanner.get_target_ip_info()

        if choice == 2:
            MyNetworkScanner.perform_ping()

        if choice == 3:
            MyNetworkScanner.perform_network_scan()

        if choice == 4:
            MyNetworkScanner.perform_scapy_scan()

        if choice == 5:
            MyNetworkScanner.perform_portrange_scan() #IP+Port = socket

        if choice == 6:
            MyNetworkScanner.perform_url_request()

        if choice == 7:
            MyNetworkScanner.perform_ip_geo_scan()


        continue




NetScanner = NetworkScanner()

Menu(NetScanner)

del NetScanner






