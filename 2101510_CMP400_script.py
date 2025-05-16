import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import matplotlib.pyplot as plt
from tabulate import tabulate
import numpy as np
import itertools
import math
import nmap
import concurrent.futures
import paramiko
import time
import nmap
import re
from telnetlib import Telnet
import random
import string

class MainMenu:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Toolkit")

        self.frame = tk.Frame(root)
        self.frame.pack(padx=40, pady=40)

        title = tk.Label(self.frame, text="Welcome to the Network Toolkit", font=("Arial", 18))
        title.pack(pady=(0, 20))

        planner_btn = tk.Button(self.frame, text="Launch Network Planner", font=("Arial", 12), width=25,
                                command=self.launch_planner)
        planner_btn.pack(pady=10)
        
        mapper_btn = tk.Button(self.frame, text="Launch Network Mapper", font=("Arial", 12), width=25,
                               command=self.launch_mapper)
        mapper_btn.pack(pady=10)

        Config_btn = tk.Button(self.frame, text="Launch Network Configuration", font=("Arial", 12), width=25,
                               command=self.config)
        Config_btn.pack(pady=10)

    def launch_planner(self):
        self.frame.destroy()
        NetworkPlannerApp(self.root)
    
    def launch_mapper(self):
        self.frame.destroy()
        Mapper(self.root)
    
    def config(self):
        messagebox.showinfo("running configuration", "Running The Configuration file")
        Config(self.root)
        messagebox.showinfo("Config Complete", "Configuration Complete")



class Config:
    def __init__(self, root):
        self.root = root
        self.devices = self.load_devices_from_file("ip_assignments.txt")
        self.ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        self.nm = nmap.PortScanner()
        self.run()

    def generate_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(characters) for _ in range(16))
    def configure_firewall(self, connection, firewall_level, network_needs, device):
        """Configure firewall based on security level and network needs"""        

        # Base firewall rules
        if (device == "switch" and firewall_level == "High") or (device == 'router'):
            connection.send("ip access-list extended BASE_FW\n")
            time.sleep(.5)
            connection.send("permit icmp any any\n")  # Allow ping
            time.sleep(.5)
            connection.send("permit tcp any any eq 22\n")  # Allow SSH
            time.sleep(.5)
            connection.send("deny ip any any log\n")  # Deny and log everything else
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)

            # Apply base firewall to external interface
            connection.send("interface FastEthernet0/0\n")
            time.sleep(.5)
            connection.send("ip access-group BASE_FW in\n")
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)
        if (firewall_level == 'Moderate' and device == 'router') or firewall_level.lower() == 'High':
            # Create stricter rules for moderate level
            connection.send("ip access-list extended MODERATE_FW\n")
            time.sleep(.5)
            
            # Allow specific services based on network needs
            if "Web Hosting" in network_needs:
                connection.send("permit tcp any any eq 80\n")
                time.sleep(.5)
                connection.send("permit tcp any any eq 443\n")
                time.sleep(.5)
            if "File Sharing" in network_needs:
                connection.send("permit tcp any any eq 445\n")
                time.sleep(.5)
                connection.send("permit udp any any eq 445\n")
                time.sleep(.5)
            if "Database" in network_needs:
                connection.send("permit tcp any any eq 3306\n")
                time.sleep(.5)
            
            
            time.sleep(.5)
            connection.send("permit icmp any any\n")  # Allow ping
            time.sleep(.5)
            connection.send("permit tcp any any eq 22\n")  # Allow SSH
            time.sleep(.5)
            connection.send("deny ip any any log\n")
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)

            # Apply moderate firewall to all interfaces
            connection.send("interface range FastEthernet0/0\n")
            time.sleep(.5)
            connection.send("ip access-group MODERATE_FW in\n")
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)

        connection.send("end\n")
        time.sleep(0.5)

    def configure_switch(self, device):
        ip = device['ip']
        firewall_level = device['firewall_level']
        network_needs = device['network_needs']
        
        print(f"\nConfiguring router at {ip} (Firewall: {firewall_level}, Needs: {network_needs})")
        admin_pass = self.generate_password()
        guest_pass = self.generate_password()

        # First try Telnet for basic SSH setup
        try:
            print("Attempting Telnet connection for initial setup...")
            tn = Telnet(host=ip, port=23, timeout=10)
            VtyUsername = simpledialog.askstring("Input", "Please enter the Virtual Terminal username: ")
            tn.write(VtyUsername.encode('ascii') + b"\n")
            VtyPassword = simpledialog.askstring("Input", "Please enter the Virtual Terminal password: ")
            tn.write(VtyPassword.encode('ascii') + b"\n")
            
            # Basic configuration to enable SSH
            tn.write(b"enable\n")
            time.sleep(.5)
            tn.write(b"configure terminal\n")
            time.sleep(.5)
            tn.write(b"ip domain-name CAM\n")
            time.sleep(.5)
            tn.write(b"crypto key generate rsa\n")
            time.sleep(.5)
            tn.write(b"1024\n")
            time.sleep(.5)
            tn.write(b"ip ssh version 2\n")
            time.sleep(.5)
            tn.write(b"username admin privilege 15 secret " + admin_pass.encode('ascii') + b"\n")
            time.sleep(.5)
            tn.write(b"username Guest privilege 0 secret " + guest_pass.encode('ascii') + b"\n")
            time.sleep(.5)
            tn.write(b"line vty 0 4\n")
            time.sleep(.5)
            tn.write(b"transport input ssh\n")
            time.sleep(.5)
            tn.write(b"login local\n")
            time.sleep(.5)
            tn.write(b"exit\n")
            time.sleep(.5)
            tn.write(b"end\n")
            time.sleep(.5)
            tn.write(b"write mem\n")
            time.sleep(.5)
            tn.write(b"exit\n")
            time.sleep(.5)
            print("Basic SSH configuration complete via Telnet")
            tn.close()
        except Exception as e:
            print(f"Telnet configuration failed: {e}")

        # Now connect via SSH for full configuration
        try:
            print("Attempting SSH connection for full configuration...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip, port=22, username="admin", password="admin", 
                          look_for_keys=False, allow_agent=False, timeout=10)
            connection = client.invoke_shell()

            # Basic router configuration
            connection.send("configure terminal\n")
            time.sleep(0.5)
            
            connection.send("no enable password\n")
            time.sleep(.5)
            connection.send("enable secret cisco\n")
            time.sleep(.5)
            connection.send("banner motd ^WARNING: Unauthorized access prohibited!^\n")
            time.sleep(.5)
            connection.send("logging buffered 16384\n")
            time.sleep(.5)
            connection.send("no ip source-route\n")
            time.sleep(.5)
            connection.send("ip routing\n")
            time.sleep(.5)
            connection.send("no service tcp-small-servers\n")
            time.sleep(.5)
            connection.send("no service udp-small-servers\n")
            time.sleep(.5)
            connection.send("no service finger\n")
            time.sleep(.5)
            connection.send("no cdp run\n")
            time.sleep(.5)


            # Configure loopback interface
            connection.send("interface Loopback0\n")
            time.sleep(.5)
            connection.send("ip address 1.1.1.1 255.255.255.255\n")
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)

            # Configure firewall
            if firewall_level == "High":
                self.configure_firewall(connection, firewall_level, network_needs, device)

            # Save configuration
            connection.send("end\n")
            connection.send("write mem\n")
            time.sleep(1)

            # Get output
            output = connection.recv(65535).decode('utf-8')
            print(f"\nRouter configuration complete for {ip}:\n{output}")

            # Save config to file
            with open(f"{ip}_router_config.txt", "w") as file:
                file.write(f"Router IP: {ip}\n")
                file.write(f"Firewall Level: {firewall_level}\n")
                file.write(f"Network Needs: {', '.join(network_needs)}\n")
                file.write(f"Admin username: admin\nAdmin password: {admin_pass}\n")
                file.write(f"Guest username: Guest\nGuest password: {guest_pass}\n")

            print(f"Configuration saved to {ip}_router_config.txt")

        except Exception as e:
            print(f"SSH configuration failed: {e}")
        finally:
            try:
                client.close()
            except:
                pass


    def configure_router(self, device):
        ip = device['ip']
        firewall_level = device['firewall_level']
        network_needs = device['network_needs']
        device_type = device['device_type']
        
        print(f"\nConfiguring router at {ip} (Firewall: {firewall_level}, Needs: {network_needs})")
        admin_pass = self.generate_password()
        guest_pass = self.generate_password()

        # First try Telnet for basic SSH setup
        try:
            print("Attempting Telnet connection for initial setup...")
            tn = Telnet(host=ip, port=23, timeout=10)
            VtyUsername = simpledialog.askstring("Input", "Please enter the Virtual Terminal username: ")
            tn.write(VtyUsername.encode('ascii') + b"\n")
            VtyPassword = simpledialog.askstring("Input", "Please enter the Virtual Terminal password: ")
            tn.write(VtyPassword.encode('ascii') + b"\n")
            
            # Basic configuration to enable SSH
            tn.write(b"enable\n")
            time.sleep(.5)
            tn.write(b"configure terminal\n")
            time.sleep(.5)
            tn.write(b"ip domain-name CAM\n")
            time.sleep(.5)
            tn.write(b"crypto key generate rsa\n")
            time.sleep(.5)
            tn.write(b"1024\n")
            time.sleep(.5)
            tn.write(b"ip ssh version 2\n")
            time.sleep(.5)
            tn.write(b"username admin privilege 15 secret admin\n") #+ admin_pass.encode('ascii') + b"\n")
            time.sleep(.5)
            tn.write(b"username Guest privilege 0 secret " + guest_pass.encode('ascii') + b"\n")
            time.sleep(.5)
            tn.write(b"line vty 0 4\n")
            time.sleep(.5)
            tn.write(b"transport input ssh\n")
            time.sleep(.5)
            tn.write(b"login local\n")
            time.sleep(.5)
            tn.write(b"exit\n")
            time.sleep(.5)
            tn.write(b"end\n")
            time.sleep(.5)
            tn.write(b"write mem\n")
            time.sleep(.5)
            tn.write(b"exit\n")
            time.sleep(.5)
            print("Basic SSH configuration complete via Telnet")
            tn.close()
        except Exception as e:
            print(f"Telnet configuration failed: {e}")

        # Now connect via SSH for full configuration
        try:
            print("Attempting SSH connection for full configuration...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ip, port=22, username="admin", password="admin", 
                          look_for_keys=False, allow_agent=False, timeout=10)
            connection = client.invoke_shell()

            # Basic router configuration
            connection.send("configure terminal\n")
            time.sleep(0.5)       
            connection.send("no enable password\n")
            time.sleep(.5)
            connection.send("enable secret cisco\n")
            time.sleep(.5)
            connection.send("banner motd ^WARNING: Unauthorized access prohibited!^\n")
            time.sleep(.5)
            connection.send("logging buffered 16384\n")
            time.sleep(.5)
            connection.send("no ip source-route\n")
            time.sleep(.5)
            connection.send("ip routing\n")
            time.sleep(.5)
            connection.send("no service tcp-small-servers\n")
            time.sleep(.5)
            connection.send("no service udp-small-servers\n")
            time.sleep(.5)
            connection.send("no service finger\n")
            time.sleep(.5)
            connection.send("no cdp run\n")
            time.sleep(.5)
            
            # Configure loopback interface
            connection.send("interface Loopback0\n")
            time.sleep(.5)
            connection.send("ip address 1.1.1.1 255.255.255.255\n")
            time.sleep(.5)
            connection.send("exit\n")
            time.sleep(.5)

            # Configure firewall
            self.configure_firewall(connection, firewall_level, network_needs, device_type)

            # Save configuration
            connection.send("end\n")
            connection.send("write mem\n")
            time.sleep(1)

            # Get output
            output = connection.recv(65535).decode('utf-8')
            print(f"\nRouter configuration complete for {ip}:\n{output}")

            # Save config to file
            with open(f"{ip}_Device_config.txt", "w") as file:
                file.write(f"Router IP: {ip}\n")
                file.write(f"Firewall Level: {firewall_level}\n")
                file.write(f"Network Needs: {', '.join(network_needs)}\n")
                file.write(f"Admin username: admin\nAdmin password: {admin_pass}\n")
                file.write(f"Guest username: Guest\nGuest password: {guest_pass}\n")

            print(f"Configuration saved to {ip}_router_config.txt")

        except Exception as e:
            print(f"SSH configuration failed: {e}")
        finally:
            try:
                client.close()
            except:
                pass


    def validate_ip(self, ip):
        """Validate IP address format"""
        return bool(self.ip_pattern.match(ip))

    def run(self):
        """Main method to configure all devices"""
        if not self.devices:
            print("No devices to configure!")
            return
            
        for device in self.devices:
            if not self.validate_ip(device['ip']):
                print(f"\nInvalid IP skipped: {device['ip']}")
                continue
                
            if device['device_type'] == 'router':
                self.configure_router(device)
            elif device['device_type'] == 'switch':
                self.configure_switch(device)
            else:
                print(f"\nUnknown device type skipped: {device['device_type']}")

    def load_devices_from_file(self, filename):
        """Load devices from file with format: name|ip|type"""
        devices = []
        try:
            with open(filename, 'r') as file:
                lines = [line.strip() for line in file.readlines() if line.strip()]
                
                # Last line contains firewall level and network needs
                if lines:
                    last_line = lines[-1]
                    if '|' in last_line:
                        firewall_level, needs_str = last_line.split('|')
                        firewall_level = firewall_level.strip()
                        network_needs = [need.strip() for need in needs_str.strip("[]").split(',')]
                    else:
                        firewall_level = 'Low'
                        network_needs = []
                    
                    # Process device entries
                    for line in lines[:-1]:
                        if '|' not in line:
                            continue
                        name, ip, device_type = map(str.strip, line.split('|'))
                        devices.append({
                            'name': name,
                            'ip': ip,
                            'device_type': device_type.lower(),
                            'firewall_level': firewall_level,
                            'network_needs': network_needs
                        })
                return devices
        except FileNotFoundError:
            print(f"Error: File {filename} not found!")
            return []
        except Exception as e:
            print(f"Error reading device file: {e}")
            return []

class NetworkPlannerApp:
    def __init__(self, root):
        self.root = root
        root.title("Network Planning Tool")

        self.question_index = 0
        self.answers = {}
        self.frames = []

        self.questions = [
            {"key": "Workstations", "text": "How many workstations (desktops) will be present on this network?", 
             "type": "entry", "help": "Enter the total number of workstations (computers) that need to be connected."},
            
            {"key": "Scalability", "text": "How much scalability (future growth) do you need?", "type": "options",
             "options": ["Low/None (6:1 workstations to switch)", "Moderate (4:1)", "High (2:1)"],
             "help": "Low: 6 workstations per switch\nModerate: 4 workstations per switch\nHigh: 2 workstations per switch"},
            
            {"key": "Redundancy", "text": "How much redundancy (fault tolerance) do you require?", "type": "options",
             "options": ["Low", "Moderate", "High"],
             "help": "Low: Basic connections\nModerate: Redundant paths between switches\nHigh: Full mesh with redundant servers"},
            
            {"key": "Security", "text": "What level of security do you need?", "type": "options",
             "options": ["Low", "Moderate", "High"],
             "help": "Basic: Perimeter firewall only\nStandard: Internal segmentation with ACLs\nHigh: Per-device controls and zones"},
            
            {"key": "ServerNeeds", "text": "What server services will you need?", "type": "checklist",
             "options": ["File Sharing", "Web Hosting", "Database"],
             "help": "Select all server services that will be required on your network"}
        ]

        self.build_ui()

    def build_ui(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=20, pady=20)

        self.label = tk.Label(self.main_frame, text="", font=("Arial", 14), wraplength=500)
        self.label.pack(pady=10)

        self.input_var = tk.StringVar()
        self.input_widget = None
        self.checkboxes = []

        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        self.back_button = tk.Button(self.button_frame, text="Back", command=self.prev_question)
        self.back_button.grid(row=0, column=0, padx=5)

        self.next_button = tk.Button(self.button_frame, text="Next", command=self.next_question)
        self.next_button.grid(row=0, column=1, padx=5)

        self.help_button = tk.Button(self.button_frame, text="Help", command=self.show_help)
        self.help_button.grid(row=0, column=2, padx=5)

        self.display_question()

    def show_help(self):
        q = self.questions[self.question_index]
        messagebox.showinfo("Help", q.get("help", "No help available for this question."))

    def display_question(self):
        self.clear_input()

        if self.question_index >= len(self.questions):
            self.show_summary()
            return

        q = self.questions[self.question_index]
        self.label.config(text=q["text"])

        if q["type"] == "entry":
            self.input_widget = tk.Entry(self.main_frame, textvariable=self.input_var, font=("Arial", 12))
            self.input_widget.pack()
        elif q["type"] == "options":
            self.input_widget = tk.OptionMenu(self.main_frame, self.input_var, *q["options"])
            self.input_var.set(q["options"][0])
            self.input_widget.pack()
        elif q["type"] == "checklist":
            self.input_widget = tk.Frame(self.main_frame)
            self.checkboxes = []
            for option in q["options"]:
                var = tk.IntVar()
                cb = tk.Checkbutton(self.input_widget, text=option, variable=var)
                cb.pack(anchor="w")
                self.checkboxes.append((option, var))
            self.input_widget.pack()

        prev_answer = self.answers.get(q["key"])
        if prev_answer:
            if q["type"] == "checklist":
                for option, var in self.checkboxes:
                    if option in prev_answer:
                        var.set(1)
            else:
                self.input_var.set(prev_answer)

        self.back_button.config(state="normal" if self.question_index > 0 else "disabled")

    def clear_input(self):
        if self.input_widget:
            self.input_widget.destroy()
            self.input_widget = None
        self.input_var.set("")
        self.checkboxes = []

    def next_question(self):
        q = self.questions[self.question_index]
        q_key = q["key"]

        if q["type"] == "entry":
            answer = self.input_var.get().strip()
            if q_key == "Workstations":
                if not answer.isdigit() or int(answer) <= 0:
                    messagebox.showerror("Invalid input", "Please enter a valid positive number of workstations.")
                    return
                answer = int(answer)
        elif q["type"] == "checklist":
            answer = [option for option, var in self.checkboxes if var.get() == 1]
            if not answer and q_key == "ServerNeeds":
                answer = ["None"]
        else:
            answer = self.input_var.get()

        self.answers[q_key] = answer
        self.question_index += 1
        self.display_question()

    def prev_question(self):
        self.question_index -= 1
        self.display_question()

    def show_summary(self):
        self.clear_input()
        self.label.config(text="Network Planning Summary:")

        summary_text = ""
        for key, val in self.answers.items():
            if isinstance(val, list):
                val = ", ".join(val)
            summary_text += f"{key}: {val}\n"

        summary_label = tk.Label(self.main_frame, text=summary_text, font=("Arial", 12), justify="left")
        summary_label.pack(pady=10)

        self.back_button.config(state="normal")
        self.next_button.config(text="Generate Network", command=self.generate_network)
        self.help_button.config(state="disabled")


    def generate_network(self):
        # Get all answers
        workstations = self.answers["Workstations"]
        scalability = self.answers["Scalability"]
        redundancy = self.answers["Redundancy"]
        security = self.answers["Security"]
        server_needs = self.answers["ServerNeeds"]

        if "Low/None" in scalability:
            ws_per_switch = 6
        elif "Moderate" in scalability:
            ws_per_switch = 4
        else:  # High
            ws_per_switch = 2
                    
        # Calculate number of switches needed
        num_switches = math.ceil(workstations / ws_per_switch)
        num_routers = math.ceil(num_switches / 3)



        #determine architectur
        if (("Web Hosting" not in server_needs and "Database" not in server_needs and workstations <= 108 and "High" in redundancy and "Low/None" in scalability) or 
                    ( "Web Hosting" not in server_needs and "Database" not in server_needs and workstations <= 72 and "High" in redundancy and "Moderate" in scalability) or 
                    ( "Web Hosting" not in server_needs and "Database" not in server_needs  and workstations <= 36 and "High" in redundancy and "High" in scalability)):
            branch_angles_deg=[-30, 0, 30, 60]
            router_radius=50
            switch_distance=50
            workstation_distance=10
            angles = np.linspace(0, 2 * np.pi, 6, endpoint=False)
            router_positions = [(np.cos(a) * router_radius, np.sin(a) * router_radius) for a in angles[:num_routers]]
    
            plt.figure(figsize=(12, 12))
            connections = []
            switch_positions = []
    
            # IP counters
            network_counter = 1  # For 3rd octet
            interface_counter = 1  # For 4th octet
    
            switch_count = 1
            firewall_count = 1
            workstation_count = 1

            # Process each router sequentially
            for router_num in range(num_routers):
                rx, ry = router_positions[router_num]
                router_name = f"Router{router_num+1}"
        
                router_switches = []  # Track switch names and positions for intra-switch connections


                # 1. Draw the router
                plt.scatter(rx, ry, color='blue')
                plt.text(rx, ry, router_name, fontsize=10, ha='center', va='center', 
                    bbox=dict(boxstyle="round", facecolor="lightgrey"))
        
                # 2. Connect switches to this router
                for j, offset in enumerate(branch_angles_deg):
                    angle = np.arctan2(ry, rx) + np.deg2rad(offset)  # This should result in a scalar
                    x = rx + np.cos(angle) * switch_distance
                    y = ry + np.sin(angle) * switch_distance

                    if j < 3 and switch_count <= num_switches:  # Switch branches
                        switch_name = f"Switch{switch_count}"
                
                        if security == 'High':
                            # With firewall between router and switch
                            mx, my = (rx + x)*0.7, (ry + y)*0.7
                            fw_name = f"FW{firewall_count}"
                    
                            plt.scatter(mx, my, color='red')
                            plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                    
                            # Router to Firewall
                            plt.plot([rx, mx], [ry, my], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((rx+mx)/2, (ry+my)/2, f"{ip1}", 
                                fontsize=7, ha='center', color='purple')

                            interface_counter += 1
                    
                            # Firewall to Switch
                            plt.plot([mx, x], [my, y], 'black')
                            interface_counter += 1
                    
                            firewall_count += 1
                        else:
                            # Direct router-switch connection
                            plt.plot([rx, x], [ry, y], 'black')
                            ip1 = f"192.168.{network_counter}.1"
                            ip2 = f"192.168.{network_counter}.2"
                            plt.text((rx+x)/2, (ry+y)/2, f"{ip1}/{ip2}", 
                                fontsize=7, ha='center', color='purple')
                            connections.append({
                                'name' :switch_name,
                                'ip' : ip2,
                                'type' : 'switch'
                            })
                            network_counter += 1
                
                        # Draw switch
                        plt.scatter(x, y, color='green')
                        plt.text(x, y, switch_name, fontsize=8, ha='center', va='center',
                                bbox=dict(boxstyle="round", facecolor="lightyellow"))
                
                        switch_positions.append((x, y, switch_name))
                        switch_count += 1
                        router_switches.append((x, y, switch_name))
                        switch_positions.append((x, y, switch_name))
                        ws_list = []  # Store workstation names and positions for interconnections

                        # 3. Connect workstations to this switch
                        for k in range(6):
                            if workstation_count > workstations:
                                break
                        
                            angle = k * (2 * np.pi / 6)
                            wx = x + np.cos(angle) * workstation_distance
                            wy = y + np.sin(angle) * workstation_distance
                            ws_name = f"WS{workstation_count}"
                    
                            # Draw workstation and connection
                            plt.scatter(wx, wy, color='orange')
                            plt.plot([x, wx], [y, wy], 'brown')
                            plt.text(wx, wy, ws_name, fontsize=7, ha='center', va='center',
                                    bbox=dict(boxstyle="round", facecolor="mistyrose"))
                    
                            # Assign IPs
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            ip2 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((x+wx)/2, (y+wy)/2, f"{ip1}/{ip2}", 
                                fontsize=6, ha='center', color='brown')
                            connections.append({
                                'name': ws_name,
                                'ip': ip2,
                                'type': 'workstation'
                            })
                            ws_list.append((wx, wy, ws_name))
                            network_counter +=1
                            interface_counter = 1

                            workstation_count += 1

                            # Connect each workstation to every other on this switch
                            for i in range(len(ws_list)):
                                for j in range(i + 1, len(ws_list)):
                                    x1, y1, ws1 = ws_list[i]
                                    x2, y2, ws2 = ws_list[j]
                                    plt.plot([x1, x2], [y1, y2], linestyle='dotted', color='gray', linewidth=0.8)


                    elif j == 3:  # Firewall stub
                        fw_name = f"FW{firewall_count}"
                        plt.scatter(x, y, color='red')
                        plt.plot([rx, x], [ry, y], 'darkred', linewidth=2)
                        plt.text(x, y, fw_name, fontsize=9, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                
                        ip1 = f"192.168.{network_counter}.1"
                        plt.text((rx+x)*0.4, (ry+y)*0.4, f"{ip1}", 
                            fontsize=7, ha='center', color='darkred')
                        connections.append({
                                'name': router_name,
                                'ip': ip1,
                                'type': 'router'
                        })
                        network_counter += 1
                        interface_counter = 1
                        firewall_count += 1


                for i, (x1, y1, sw1) in enumerate(router_switches):
                    for j in range(i + 1, len(router_switches)):
                        x2, y2, sw2 = router_switches[j]

                        # Draw connection
                        plt.plot([x1, x2], [y1, y2], 'darkgreen', linestyle='--')

                        network_counter += 1
                        interface_counter = 1
            # Connect routers to each other
            for i, j in itertools.combinations(range(num_routers), 2):
                r1, r2 = router_positions[i], router_positions[j]
                router1, router2 = f"Router{i+1}", f"Router{j+1}"
        
                if security in ['Moderate', 'High']:
                    # With firewall between routers
                    mx, my = (r1[0]+r2[0])/2, (r1[1]+r2[1])/2
                    fw_name = f"FW{firewall_count}"
            
                    plt.scatter(mx, my, color='red')
                    plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                        bbox=dict(boxstyle="round", facecolor="salmon"))
            
                    # Router1 to Firewall
                    plt.plot([r1[0], mx], [r1[1], my], 'gray')
                    ip1 = f"192.168.{network_counter}.{interface_counter}"
                    plt.text((r1[0]+mx)/2, (r1[1]+my)/2, f"{ip1}", 
                        fontsize=7, ha='center', color='darkblue')
                    interface_counter += 1
                    # Firewall to Router2
                    plt.plot([mx, r2[0]], [my, r2[1]], 'gray')
                    ip2 = f"192.168.{network_counter}.1"
                    plt.text((mx+r2[0])/2, (my+r2[1])/2, f"{ip2}", 
                        fontsize=7, ha='center', color='darkblue')
                    connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                    })
                    network_counter += 1
                    interface_counter = 1
            
                    firewall_count += 1
                else:
                    # Direct router-router connection
                    plt.plot([r1[0], r2[0]], [r1[1], r2[1]], 'gray')
                    ip1 = f"192.168.{network_counter}.1"
                    ip2 = f"192.168.{network_counter}.2"
                    plt.text((r1[0]+r2[0])/2, (r1[1]+r2[1])/2, f"{ip1}/{ip2}", 
                        fontsize=7, ha='center', color='darkblue')
                    connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                    })
                network_counter += 1
                interface_counter = 1

            plt.title(f"Hex Network\n"
              f"Security: {security.capitalize()}, "
              f"Scalability: {redundancy.capitalize()}\n"
              f"{num_routers} Routers, {num_switches} Switches, {workstations} Workstations")
            plt.axis('equal')
            plt.axis('off')
            plt.tight_layout()
            plt.show()
        elif "Web Hosting" not in server_needs and "Database" not in server_needs:
            # Place routers in a straight horizontal line
            branch_angles_deg=[-30, 0, 30, 60]

            router_spacing=15
            switch_distance=6
            workstation_distance=3
            router_positions = [(i * router_spacing, 0) for i in range(num_routers)]
            router_names = [f"Router{i+1}" for i in range(num_routers)]
    
            plt.figure(figsize=(12, 8))
            connections = []
            all_switch_groups = []
            switch_positions = []
    
            # IP counters
            network_counter = 1  # For 3rd octet
            interface_counter = 1  # For 4th octet
    
            switch_count = 1
            firewall_count = 1
            workstation_count = 1

            # Process each router's switches and workstations first
            for router_num in range(num_routers):
                rx, ry = router_positions[router_num]
                router_name = router_names[router_num]
        
                # Draw the router
                plt.scatter(rx, ry, color='blue', s=100)
                plt.text(rx, ry, router_name, fontsize=10, ha='center', va='center', 
                    bbox=dict(boxstyle="round", facecolor="lightgrey"))
        
                # Connect switches to this router
                switch_group1 = []
                switch_group2 = []
                base_angle = np.pi/2  # Pointing upwards
                for j, offset in enumerate(branch_angles_deg):
                    angle = base_angle + np.deg2rad(offset)
                    x = rx + np.cos(angle) * switch_distance
                    y = ry + np.sin(angle) * switch_distance

                    if j < 3 and switch_count <= num_switches:  # Switch branches
                        switch_name = f"Switch{switch_count}"
                
                        if security == 'High':
                            # With firewall between router and switch
                            mx, my = (rx + x)*0.7, (ry + y)*0.7
                            fw_name = f"FW{firewall_count}"
                    
                            plt.scatter(mx, my, color='red', s=80)
                            plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                            # Router to Firewall
                            plt.plot([rx, mx], [ry, my], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((rx+mx)/2, (ry+my)/2, f"{ip1}", 
                                fontsize=7, ha='center', color='purple')
                            interface_counter +=1
                    
                            # Firewall to Switch
                            plt.plot([mx, x], [my, y], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            ip2 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((mx+x)/2, (my+y)/2, f"{ip2}", 
                                fontsize=7, ha='center', color='purple')
                            interface_counter =1
                            firewall_count += 1

                        else:
                            # Direct router-switch connection (low/moderate)
                            plt.plot([rx, x], [ry, y], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            ip2 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((rx+x)/2, (ry+y)/2, f"{ip1}/{ip2}", 
                                fontsize=7, ha='center', color='purple')
                            connections.append({
                                'name': switch_name,
                                'ip': ip2,
                                'type': 'switch'
                            })
                        network_counter += 1
                        interface_counter = 1
                        # Draw switch
                        plt.scatter(x, y, color='green', s=80)
                        plt.text(x, y, switch_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="lightyellow"))
                
                        switch_positions.append((x, y, switch_name))
                        switch_group1.append((x, y, switch_name))
                        switch_group2.append((x, y, switch_name))

                        switch_count += 1
                        # Connect workstations to switches
                        for sx, sy, switch_name in switch_group2:
                            for k in range(ws_per_switch):
                                if workstation_count > workstations:
                                    break
                                angle = k * (2 * np.pi / ws_per_switch)
                                wx = sx + np.cos(angle) * workstation_distance
                                wy = sy + np.sin(angle) * workstation_distance
                                ws_name = f"WS{workstation_count}"
                
                                # Draw workstation and connection
                                plt.scatter(wx, wy, color='orange', s=60)
                                plt.plot([sx, wx], [sy, wy], 'brown')
                                plt.text(wx, wy, ws_name, fontsize=7, ha='center', va='center',
                                    bbox=dict(boxstyle="round", facecolor="mistyrose"))
                
                                # Assign IPs
                                ip1 = f"192.168.{network_counter}.{interface_counter}"
                                interface_counter += 1
                                ip2 = f"192.168.{network_counter}.{interface_counter}"
                                interface_counter += 1
                                plt.text((sx+wx)/2, (sy+wy)/2, f"{ip1}/{ip2}", 
                                    fontsize=6, ha='center', color='brown')
                                connections.append({
                                'name': ws_name,
                                'ip': ip2,
                                'type': 'workstation'
                                })
                                network_counter +=1
                
                                workstation_count += 1
                                

                    elif j == 3:  # Firewall stub (always present)
                        fw_name = f"FW{firewall_count}"
                        plt.scatter(x, y, color='red', s=80)
                        plt.plot([rx, x], [ry, y], 'darkred', linewidth=2)
                        plt.text(x, y, fw_name, fontsize=9, ha='center', va='center',
                                bbox=dict(boxstyle="round", facecolor="salmon"))
                
                        ip1 = f"192.168.{network_counter}.1"
                        plt.text((rx+x)*0.4, (ry+y)*0.4, f"{ip1}", 
                            fontsize=7, ha='center', color='darkred')
                        connections.append({
                                'name': router_name,
                                'ip': ip1,
                                'type': 'router'
                        })
                        network_counter += 1
                        interface_counter = 1
                        firewall_count += 1
                    switch_group2 = []

                # Add switch-to-switch connections for moderate redundancy
                if redundancy == 'Moderate' and len(switch_group1) > 1:
                    for (x1, y1, sw1), (x2, y2, sw2) in itertools.combinations(switch_group1, 2):
                        plt.plot([x1, x2], [y1, y2], color='lightgreen', linestyle='dashed')

                all_switch_groups.append(switch_group1)

            for i in range(num_routers - 1):
                router1 = router_names[i]
                router2 = router_names[i + 1]
                r1 = router_positions[i]
                r2 = router_positions[i + 1]

                if security in ['Moderate', 'High']:
                    # Add firewall between routers
                    mx, my = (r1[0]+r2[0])/2, (r1[1]+r2[1])/2
                    fw_name = f"FW{firewall_count}"

                    plt.scatter(mx, my, color='red', s=80)
                    plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                             bbox=dict(boxstyle="round", facecolor="salmon"))

                    # Router1 to Firewall
                    plt.plot([r1[0], mx], [r1[1], my], 'gray', linewidth=2)
                    ip1 = f"192.168.{network_counter}.1"
                    plt.text((r1[0]+mx)/2, (r1[1]+my)/2, f"{ip1}",
                     fontsize=7, ha='center', color='darkblue')

                 # Firewall to Router2
                    plt.plot([mx, r2[0]], [my, r2[1]], 'gray', linewidth=2)
                    ip2 = f"192.168.{network_counter}.2"
                    plt.text((mx+r2[0])/2, (my+r2[1])/2, f"{ip2}",
                             fontsize=7, ha='center', color='darkblue')
                    connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                    })

                    firewall_count += 1
                    network_counter += 1

                else:
                    # Direct router-to-router connection
                    plt.plot([r1[0], r2[0]], [r1[1], r2[1]], 'gray', linewidth=2)
                    ip1 = f"192.168.{network_counter}.1"
                    ip2 = f"192.168.{network_counter}.2"
                    plt.text((r1[0]+r2[0])/2, (r1[1]+r2[1])/2, f"{ip1}/{ip2}",
                             fontsize=7, ha='center', color='darkblue')
                    connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                    })
                    network_counter += 1

            plt.title(f"Linear Network\n"
                    f"Security: {security.capitalize()}, "
                    f"Redundancy: {redundancy.capitalize()}, "
                    f"Scalability: {scalability.capitalize()}\n"
                    f"{num_routers} Routers, {num_switches} Switches, {workstations} Workstations")
            plt.axis('equal')
            plt.axis('off')
            plt.tight_layout()
            plt.show()

        else:
            router_spacing=15
            switch_distance=6
            workstation_distance=3
            branch_angles_deg=[-30, 0, 30, 60]

            # Place routers in a straight horizontal line
            router_positions = [(i * router_spacing, 0) for i in range(num_routers)]
            router_names = [f"Router{i+1}" for i in range(num_routers)]
    
            plt.figure(figsize=(12, 8))
            connections = []
            all_switch_groups = []
            switch_positions = []
    
            # IP counters
            network_counter = 1  # For 3rd octet
            interface_counter = 1  # For 4th octet
    
            switch_count = 1
            firewall_count = 1
            workstation_count = 1

            # Process each router's switches and workstations first
            for router_num in range(num_routers):
                rx, ry = router_positions[router_num]
                router_name = router_names[router_num]
        
                # Draw the router
                plt.scatter(rx, ry, color='blue', s=100)
                plt.text(rx, ry, router_name, fontsize=10, ha='center', va='center', 
                    bbox=dict(boxstyle="round", facecolor="lightgrey"))
        
                # Connect switches to this router
                switch_group1 = []
                switch_group2 = []
                base_angle = np.pi/2  # Pointing upwards
                for j, offset in enumerate(branch_angles_deg):
                    angle = base_angle + np.deg2rad(offset)  # This should result in a scalar
                    x = rx + np.cos(angle) * switch_distance
                    y = ry + np.sin(angle) * switch_distance

                    if j < 3 and switch_count <= num_switches:  # Switch branches
                        switch_name = f"Switch{switch_count}"
                
                        if security == 'High':
                            # With firewall between router and switch
                            mx, my = (rx + x)*0.7, (ry + y)*0.7
                            fw_name = f"FW{firewall_count}"
                    
                            plt.scatter(mx, my, color='red', s=80)
                            plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                                bbox=dict(boxstyle="round", facecolor="salmon"))
                            # Router to Firewall
                            plt.plot([rx, mx], [ry, my], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((rx+mx)/2, (ry+my)/2, f"{ip1}", 
                                fontsize=7, ha='center', color='purple')

                    
                            # Firewall to Switch
                            plt.plot([mx, x], [my, y], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((mx+x)/2, (my+y)/2, f"{ip1}", 
                                fontsize=7, ha='center', color='purple')
                            connections.append({
                                'name': switch_name,
                                'ip': ip1,
                                'type': 'switch'
                            })
                            interface_counter =1
                            firewall_count += 1

                        else:
                            # Direct router-switch connection (low/moderate)
                            plt.plot([rx, x], [ry, y], 'black')
                            ip1 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            ip2 = f"192.168.{network_counter}.{interface_counter}"
                            interface_counter += 1
                            plt.text((rx+x)/2, (ry+y)/2, f"{ip1}/{ip2}", 
                                fontsize=7, ha='center', color='purple')
                            connections.append({
                                'name': switch_name,
                                'ip': ip2,
                                'type': 'switch'
                            })
                        network_counter += 1
                        interface_counter = 1
                        # Draw switch
                        plt.scatter(x, y, color='green', s=80)
                        plt.text(x, y, switch_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="lightyellow"))
                
                        switch_positions.append((x, y, switch_name))
                        switch_group1.append((x, y, switch_name))
                        switch_group2.append((x, y, switch_name))
                        ws_list = []  # Store workstation names and positions for interconnections


                        switch_count += 1
                        # Connect workstations to switches
                        for sx, sy, switch_name in switch_group2:
                            for k in range(ws_per_switch):
                                if workstation_count > workstations:
                                    break
                                angle = k * (2 * np.pi / ws_per_switch)
                                wx = sx + np.cos(angle) * workstation_distance
                                wy = sy + np.sin(angle) * workstation_distance
                                ws_name = f"WS{workstation_count}"
                
                                # Draw workstation and connection
                                plt.scatter(wx, wy, color='orange', s=60)
                                plt.plot([sx, wx], [sy, wy], 'brown')
                                plt.text(wx, wy, ws_name, fontsize=7, ha='center', va='center',
                                    bbox=dict(boxstyle="round", facecolor="mistyrose"))

                                # Assign IPs
                                ip1 = f"192.168.{network_counter}.{interface_counter}"
                                interface_counter += 1
                                ip2 = f"192.168.{network_counter}.{interface_counter}"
                                interface_counter += 1
                                plt.text((sx+wx)/2, (sy+wy)/2, f"{ip1}/{ip2}", 
                                fontsize=6, ha='center', color='brown')
                                connections.append({
                                'name': ws_name,
                                'ip': ip2,
                                'type': 'workstation'
                                })
                                network_counter +=1
                
                                ws_list.append((wx, wy, ws_name))
                                workstation_count += 1
                                # Connect each workstation to every other on this switch
                                if redundancy == "High":
                                    for i in range(len(ws_list)):
                                        for j in range(i + 1, len(ws_list)):
                                            x1, y1, ws1 = ws_list[i]
                                            x2, y2, ws2 = ws_list[j]
                                            plt.plot([x1, x2], [y1, y2], linestyle='dotted', color='gray', linewidth=0.8)
                        interface_counter =1


                    elif j == 3:  # Firewall stub (always present)
                        fw_name = f"FW{firewall_count}"
                        plt.scatter(x, y, color='red', s=80)
                        plt.plot([rx, x], [ry, y], 'darkred', linewidth=2)
                        plt.text(x, y, fw_name, fontsize=9, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                
                        ip1 = f"192.168.{network_counter}.1"
                        plt.text((rx+x)*0.4, (ry+y)*0.4, f"{ip1}", 
                            fontsize=7, ha='center', color='darkred')
                        connections.append({
                                'name': router_name,
                                'ip': ip1,
                                'type': 'router'
                        })
                        network_counter += 1
                        interface_counter = 1
                        firewall_count += 1
                    switch_group2 = []

                # Add switch-to-switch connections for moderate redundancy
                if redundancy in ['Moderate', 'High'] and len(switch_group1) > 1:
                    for (x1, y1, sw1), (x2, y2, sw2) in itertools.combinations(switch_group1, 2):
                         plt.plot([x1, x2], [y1, y2], color='lightgreen', linestyle='dashed')

                all_switch_groups.append(switch_group1)

            server_count = math.ceil(num_routers/2)
            server_positions = []
            server_router_name = None
            server_y_offset = -8  # Below the routers
            server_x_spacing = 4

            # Position servers in a horizontal row
            for i in range(server_count):
                sx = i * server_x_spacing + 2  # offset to make it visible
                sy = server_y_offset
                s_name = f"Server{i+1}"
                server_positions.append((sx, sy, s_name))

                plt.scatter(sx, sy, color='teal', s=80)
                plt.text(sx, sy, s_name, fontsize=8, ha='center', va='center',
                    bbox=dict(boxstyle="round", facecolor="lightcyan"))

            if server_count > 1:
                # Place the server router centrally
                sr_x = (server_positions[0][0] + server_positions[-1][0]) / 2
                sr_y = server_y_offset + 3
                server_router_name = "ServerRouter"
                plt.scatter(sr_x, sr_y, color='blue', s=100)
                plt.text(sr_x, sr_y, server_router_name, fontsize=10, ha='center', va='center',
                    bbox=dict(boxstyle="round", facecolor="lightgrey"))

                # Connect each server to the server router
                for sx, sy, s_name in server_positions:
                    if security == 'High':
                        # Add firewall between server and server router
                        mx, my = (sx + sr_x)*0.6, (sy + sr_y)*0.6
                        fw_name = f"FW{firewall_count}"
                
                        plt.scatter(mx, my, color='red', s=80)
                        plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                
                        # Server to Firewall
                        plt.plot([sx, mx], [sy, my], 'cyan')
                        ip1 = f"192.168.{network_counter}.{interface_counter}"
                        plt.text((sx+mx)/2, (sy+my)/2, f"{ip1}", 
                            fontsize=6, ha='center', color='teal')
                        connections.append({
                                'name': s_name,
                                'ip': ip1,
                                'type': 'server'
                        })
                        interface_counter += 1
                
                        # Firewall to Server Router
                        plt.plot([mx, sr_x], [my, sr_y], 'cyan')
                        ip2 = f"192.168.{network_counter}.{interface_counter}"
                        plt.text((mx+sr_x)/2, (my+sr_y)/2, f"{ip2}", 
                            fontsize=6, ha='center', color='teal')
                        interface_counter = 1
                        firewall_count += 1
                    else:
                        # Direct server-router connection (low/moderate)
                        plt.plot([sx, sr_x], [sy, sr_y], 'cyan')
                        ip1 = f"192.168.{network_counter}.{interface_counter}"
                        interface_counter += 1
                        ip2 = f"192.168.{network_counter}.{interface_counter}"
                        interface_counter += 1
                        plt.text((sx+sr_x)/2, (sy+sr_y)/2, f"{ip1}/{ip2}",
                            fontsize=6, ha='center', color='teal')
                        connections.append({
                                'name': s_name,
                                'ip': ip1,
                                'type': 'server'
                        })
                network_counter += 1
                interface_counter = 1

            # Connect servers to routers and track which routers belong to which server
            server_router_mapping = {}
            total_routers = len(router_names)
            routers_per_server = math.ceil(total_routers // server_count)
            for i, (sx, sy, s_name) in enumerate(server_positions):
                start_index = i * routers_per_server
                end_index = start_index + 2  # each server gets 2 routers
                connected_indices = list(range(start_index, min(end_index, total_routers)))
                server_router_mapping[s_name] = [router_names[idx] for idx in connected_indices]
        
                for idx in connected_indices:
                    router = router_names[idx]
                    rx, ry = router_positions[idx]
            
                    if security == 'High':
                        # Add firewall between server and router
                        mx, my = (sx + rx)*0.6, (sy + ry)*0.6
                        fw_name = f"FW{firewall_count}"
                
                        plt.scatter(mx, my, color='red', s=80)
                        plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                            bbox=dict(boxstyle="round", facecolor="salmon"))
                
                        # Server to Firewall
                        plt.plot([sx, mx], [sy, my], 'skyblue', linestyle='dotted')
                        ip1 = f"192.168.{network_counter}.{interface_counter}"
                        plt.text((sx+mx)/2, (sy+my)/2, f"{ip1}", 
                            fontsize=6, ha='center', color='skyblue')
                        connections.append({
                                'name': s_name,
                                'ip': ip1,
                                'type': 'server'
                        })
                        interface_counter += 1
                
                        # Firewall to Router
                        plt.plot([mx, rx], [my, ry], 'skyblue', linestyle='dotted')
                        ip2 = f"192.168.{network_counter}.{interface_counter}"
                        plt.text((mx+rx)/2, (my+ry)/2, f"{ip2}", 
                            fontsize=6, ha='center', color='skyblue')
                        interface_counter = 1
                        firewall_count += 1
                    else:
                        # Direct server-router connection (low/moderate)
                        plt.plot([sx, rx], [sy, ry], 'skyblue', linestyle='dotted')
                        ip1 = f"192.168.{network_counter}.{interface_counter}"
                        interface_counter += 1
                        ip2 = f"192.168.{network_counter}.{interface_counter}"
                        interface_counter += 1
                        plt.text((sx+rx)/2, (sy+ry)/2, f"{ip1}/{ip2}",
                        fontsize=6, ha='center', color='skyblue')
                        connections.append({
                                'name': s_name,
                                'ip': ip1,
                                'type': 'server'
                        })
                network_counter += 1
                interface_counter = 1

            # Connect routers that share the same server only when redundancy is high
            if redundancy == 'High':
                # Create a reverse mapping from router to server
                router_server_mapping = {}
                for server, routers in server_router_mapping.items():
                    for router in routers:
                        router_server_mapping[router] = server
        
                # Find all pairs of routers that share the same server
                for i in range(num_routers):
                    for j in range(i+1, num_routers):
                        router1 = router_names[i]
                        router2 = router_names[j]
                
                        # Check if both routers are connected to the same server
                        if (router1 in router_server_mapping and 
                            router2 in router_server_mapping and
                            router_server_mapping[router1] == router_server_mapping[router2]):
                    
                            r1 = router_positions[i]
                            r2 = router_positions[j]
                    
                            if security in ['Moderate', 'High']:
                                # With firewall between routers
                                mx, my = (r1[0]+r2[0])/2, (r1[1]+r2[1])/2
                                fw_name = f"FW{firewall_count}"
                        
                                plt.scatter(mx, my, color='red', s=80)
                                plt.text(mx, my, fw_name, fontsize=8, ha='center', va='center',
                                    bbox=dict(boxstyle="round", facecolor="salmon"))
                        
                                # Router1 to Firewall
                                plt.plot([r1[0], mx], [r1[1], my], 'gray', linewidth=2)
                                ip1 = f"192.168.{network_counter}.1"
                                plt.text((r1[0]+mx)/2, (r1[1]+my)/2, f"{ip1}", 
                                    fontsize=7, ha='center', color='darkblue')
                        
                                # Firewall to Router2
                                plt.plot([mx, r2[0]], [my, r2[1]], 'gray', linewidth=2)
                                ip2 = f"192.168.{network_counter}.2"
                                plt.text((mx+r2[0])/2, (my+r2[1])/2, f"{ip2}", 
                                    fontsize=7, ha='center', color='darkblue')
                                connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                                })
                                firewall_count += 1
                                network_counter += 1
                            else:
                                # Direct router-router connection (low security)
                                plt.plot([r1[0], r2[0]], [r1[1], r2[1]], 'gray', linewidth=2)
                                ip1 = f"192.168.{network_counter}.1"
                                ip2 = f"192.168.{network_counter}.2"
                                plt.text((r1[0]+r2[0])/2, (r1[1]+r2[1])/2, f"{ip1}/{ip2}", 
                                    fontsize=7, ha='center', color='darkblue')
                                connections.append({
                                'name': router2,
                                'ip': ip2,
                                'type': 'router'
                                })
                                network_counter += 1

            plt.title(f"Linear Network\n"
                        f"Security: {security.capitalize()}, "
                        f"Redundancy: {redundancy.capitalize()}, "
                        f"Scalability: {scalability.capitalize()}\n"
                        f"{num_routers} Routers, {num_switches} Switches, {workstations} Workstations")
            plt.axis('equal')
            plt.axis('off')
            plt.tight_layout()
            plt.show()            
        

        # Return to main menu
        with open("ip_assignments.txt", "w") as f:
            for connection in connections:
                f.write(f"{connection['name']} | {connection['ip']} | {connection['type']}\n")
            f.write(f"{security} | {server_needs}")
        self.main_frame.destroy()
        MainMenu(self.root)


    def display_network_info(self, workstations, switches, routers, servers, firewalls, server_needs):
        info = [
            ["Workstations", workstations],
            ["Switches", switches],
            ["Routers", routers],
            ["Servers", servers],
            ["Firewalls", firewalls],
            ["Server Services", ", ".join(server_needs) if server_needs else "None"]
        ]
        
        message = "Network Configuration Summary:\n\n"
        message += tabulate(info, headers=["Component", "Quantity"], tablefmt="grid")
        
        messagebox.showinfo("Network Summary", message)


class Mapper:
    def __init__(self, root):
        self.root = root
        root.title("Network Scanner")

        self.hosts = []

        self.build_ui()

    def build_ui(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=20, pady=20)

        self.label = tk.Label(self.main_frame, text="Enter an IP address or subnet:", font=("Arial", 14))
        self.label.pack(pady=10)

        self.input_var = tk.StringVar()
        self.entry = tk.Entry(self.main_frame, textvariable=self.input_var, width=30)
        self.entry.pack(pady=5)

        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        self.add_button = tk.Button(self.button_frame, text="Add Host", command=self.add_host)
        self.add_button.grid(row=0, column=0, padx=5)

        self.discover_button = tk.Button(self.button_frame, text="Discover Subnet", command=self.discover_subnet)
        self.discover_button.grid(row=0, column=1, padx=5)

        self.finish_button = tk.Button(self.button_frame, text="Finish", command=self.finish_input)
        self.finish_button.grid(row=0, column=2, padx=5)

        self.hosts_listbox = tk.Listbox(self.main_frame, width=50)
        self.hosts_listbox.pack(pady=10)

    def add_host(self):
        ip = self.input_var.get().strip()
        if ip:
            self.hosts.append(ip)
            self.hosts_listbox.insert(tk.END, ip)
            self.input_var.set("")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")

    def discover_subnet(self):
        subnet = self.input_var.get().strip()
        if not subnet:
            messagebox.showwarning("Input Error", "Please enter a subnet (e.g., 192.168.0.0/24)")
            return

        scanner = nmap.PortScanner()
        try:
            scanner.scan(hosts=subnet, arguments="-sn")
            discovered = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]

            if not discovered:
                messagebox.showinfo("Discovery Result", "No live hosts found.")
                return

            for host in discovered:
                if host not in self.hosts:
                    self.hosts.append(host)
                    self.hosts_listbox.insert(tk.END, host)

            messagebox.showinfo("Discovery Complete", f"Discovered {len(discovered)} live host(s).")
            self.input_var.set("")

        except Exception as e:
            messagebox.showerror("Scan Error", f"Failed to scan subnet.\nError: {e}")

    def finish_input(self):
        if not self.hosts:
            messagebox.showinfo("No Hosts", "You haven't entered or discovered any IP addresses yet.")
            return

        messagebox.showinfo("Scanning", f"Scanning the following hosts:\n{', '.join(self.hosts)}")
        Mapper.run(self.hosts)

    @staticmethod
    def scan_host(host, file_handle):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(host, arguments="")
            result = f"\nHost: {host}\n"
            result += f"State: {scanner[host].state()}\n"
            for proto in scanner[host].all_protocols():
                result += f"Protocol: {proto}\n"
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    result += f"Port: {port} State: {state}\n"
            print(result)
            file_handle.write(result)
        except Exception as e:
            error_msg = f"Error scanning {host}: {e}\n"
            print(error_msg)
            file_handle.write(error_msg)

    @staticmethod
    def run(target_ips):
        scanner = nmap.PortScanner()
        live_hosts = []

        for ip in target_ips:
            try:
                scanner.scan(hosts=ip, arguments="-sn")
                if ip in scanner.all_hosts() and scanner[ip].state() == "up":
                    live_hosts.append(ip)
            except Exception as e:
                print(f"Error scanning {ip}: {e}")

        if not live_hosts:
            print("No live hosts found.")
            return

        with open("scanresults.txt", "w") as f:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(Mapper.scan_host, host, f) for host in live_hosts]
                concurrent.futures.wait(futures)

            print("\nScan results saved to scanresults.txt")


    
if __name__ == "__main__":
    root = tk.Tk()
    main_menu = MainMenu(root)
    root.mainloop()