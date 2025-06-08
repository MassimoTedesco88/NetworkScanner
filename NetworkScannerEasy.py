#PROGRAMMA CHE SCANSIONE LA NOSTRA RETE E CONTROLLA SE CI SONO FALLE COMUNI | PROGETTO di MASSIMO S. 01.06.2025
#senza l'ausilio di nmap voglio:
#1. scansionare la rete per vedere quali dispositivi sono connessi
#2. quali porte sono vulnerabili
#3. analisi del sistema, scansione porte aperte, connessioni servizi e riconoscimento delle porte effimere (temporanee)

import netifaces #per ottenere RANGE IP e IP
import ipaddress #per ottenere RANGE IP,IP, utilizzato nella funzione pingsweep
import subprocess#utilizzato nella funzione pingsweep
import platform#utilizzato nella funzione pingsweep
from scapy.all import ARP,Ether,srp#utilizzato nella funzione ARP scan
import socket#utilizzato nella funzione ARP scan e TCP scanner
import psutil #per funzione lista open port solo su IP pc

####FUNZIONI CHIAVE
############## IP RANGE IN AUTOMATICO
def get_ip_range():#funzione che ottiene IP range e IP 
    #ottieni gateway
    gateways = netifaces.gateways()
    default_iface = gateways['default'][netifaces.AF_INET][1]
    #ottini indirizzo IP e netmask
    iface_data= netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
    ip=iface_data['addr']
    netmask = iface_data['netmask']
    #calcola subnet
    network=ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    
    return str(network),str(ip)
##################PING SWEEP SVEGLIA DISPOSITIVI
def ping_ip(ip):#Ping un pacchetti, restituisce True  se riceve risposta
    if platform.system().lower() =='windows':
        param = ' -n ' 
    else:
        param = ' -c '
    command=['ping',param,'1',ip]
    result=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return result.returncode ==0

def ping_sweep(ip_range, repeat=2):#Ping a tutti IP nella subnet, per svegliare i dispositivi
    network=ipaddress.ip_network(ip_range,strict=False)
    print("****Avvio ping sweep sulla rete\n")
    for _ in range(repeat):#repeat dovrebbe aumentare la possibilità di rilevare i dispositivi connessi alla rete ma in standby(alcuni dispositivi ioS e android)
        for ip in network.hosts():
            ip_str = str(ip)        
            ping_ip(ip_str)#ping in background, ignora risposta
        
    print("Ping sweep completato!*****\n")

###################ARP SCAN INVIA RICHIESTE PER OGNI IP NEL RANGE E RACCOGLIE IP,MAC e hostname
def scan_network(ip_range):
    #scan su tutti gli ip e ritorna la lista dei dispositivi trovati
    print("N.B.: Per eseguire questo scan c'è bisogno di avere più privilegi (Admin/Root)\n")
    print("****ARP scan in esecuzione\n")
    #crea pacchetto ARP + Eth (broadcast)
    arp=ARP(pdst=ip_range)
    ether= Ether(dst="ff:ff:ff:ff:ff:ff")
    packet= ether / arp
    #invia e riceve pacchetti
    result= srp(packet, timeout=2,verbose=0)[0]
    
    devices=[]

    for sent,received in result:
        ip=received.psrc
        mac=received.hwsrc
    #risolvere nome host
        try:
            hostname= socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname="Sconosciuto" 
        vendor=get_vendor(mac)       
        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor':vendor
        })
        
    return devices

######IDENTIFICARE VENDORE DEL MAC - OUI
def get_vendor(mac):
    #dizionario base prefissi OUI noti
    #in futuro carica da file esterno
    oui_vendor ={
    "00:1A:2B": "Apple",
    "00:1B:63": "Sony",
    "00:0C:29": "VMware",
    "00:14:22": "Cisco System",
    "1C:ED:6F": "AVM Audiovisuelles Marketing und Computersysteme GmbH - Fritz.box",
    "DC:68:EB": "Nintendo Co.,Ltd",
    "74:15:75": "Xiaomi Communications Co Ltd",
    "4C:E0:DB":"Xiaomi Communications Co Ltd"
    }

    #normalizza e cerca il prefisso nei primi 3byte
    prefix = mac.upper()[0:8]
    return oui_vendor.get(prefix,"Sconosciuto")

#########SCANNER PORTE TCP
def scan_ports(ip,timeout=1):
    ##in futuro carica da file esterno
    common_ports= {
        21:"FTP",
        22:"SSH",
        23:"Telnet",
        25:"SMTP",
        53:"DNS",
        80:"HTTP",
        110:"POP3",
        139:"NetBIOS",
        143:"IMAP",
        443:"HTTPS",
        445:"SMB",
        3389:"RDP"
    }
    port_risks={
        21:("Alto","Disabilita o proteggi FTP: usa SFTP o FTPS al suo posto."),
        22:("Medio","Assicurati che SSH richieda chiavi e non accetti root login."),
        23:("Alto","Telnet è insicuro: disabilitalo e usa SSH."),
        25:("Medio","SMTP aperto? Proteggilo con autenticazione e TLS."),
        53:("Basso","DNS locale vabene, evita di esporlo a internet."),
        80:("Medio", "HTTP non cifrato: usa HTTPS"),
        110:("Alto","POP3 è obsoleto e non sicuro: disabilita o usa POP3S."),
        139:("Alto","NetBIOS è usato per Window file sharing: disabilitalo se non necessario."),
        143:("Medio", "IMAP dovrebbe usare IMAPS (porta 993)."),
        443:("Basso","HTTPS ok: verifica certificati validi."),
        445:("Alto", "SMB può esporre la rete a ransomware: disabilita se non serve."),
        3389:("Alto","RDP va protetto: usa VPN e password forti.")
    }

    open_ports=[]
    for port in port_risks:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result=s.connect_ex((ip,port))
            if result ==0:
                risk,advice = port_risks[port]
                service = common_ports.get(port,"Servizio Sconosciuto")
                open_ports.append({
                    'port':port,
                    'service':service,
                    'risk':risk,
                    'advice':advice
                })
    return open_ports

######OPEN PORTS SUL PC
def get_open_ports():
    conns=psutil.net_connections(kind='inet')#informazioni sui servizi, connessioni stabilite, porte etc
    open_ports = set()
    conns_list=[]
    for conn in conns:
    #ELENCO DI TUTTI I SERVIZI in connessione
        status=conn.status
        pid=conn.pid
        if pid:
            proc_name=psutil.Process(pid).name()
        else:
            proc_name="N/A"
        if conn.laddr:
            laddr=f"{conn.laddr.ip}:{conn.laddr.port}"
        else:
            laddr="N/A"
        if conn.raddr:
            raddr=f"{conn.raddr.ip}:{conn.raddr.port}"
        else:
            raddr="N/A"
        if conn.laddr:
            l_effe=is_ephemeral_port(conn.laddr.port)
        else:
            l_effe=False
        if conn.raddr:
            r_effe=is_ephemeral_port(conn.raddr.port)
        else:
            r_effe=False
        conn_info={
            "local_address":laddr,
            "local_ephemeral":l_effe,
            "remote_address":raddr,
            "remote_ephemeral":r_effe,
            "status":status,
            "pid":pid,
            "service":proc_name
            
        }
        conns_list.append(conn_info)
    #SE CI SONO PORTA APERTE IN ASCOLTO
        if conn.status == psutil.CONN_LISTEN:
            open_ports.add(conn.laddr.port)
    return sorted(open_ports),conns_list
def is_ephemeral_port(port):
    return 32768 <= port <= 60999 #generico, in realtà varia da OS


#esecuzioni funzioni
def operazioni():
    print("""________________[NETWORK SCANNER]_____________
Analizza la tua rete locale: 
    comunicando IP-range e IP del sistema
 -1-controlla i dispositivi connessi alla rete
 -2-controlla quali porte sono aperte e se esistono semplici vulnerabilità 
---------------------------------------------------------------------------\n""")
    ip_range,ip_this = get_ip_range()
    print(f"Range IP della rete: {ip_range} - IP del sistema: {ip_this}\n")
    print("Porte TCP/UDP aperte qui:")
    porteAperte,conns_list=get_open_ports()
    print(porteAperte)
    for c in conns_list:
        print(f"{c}")


    ping_sweep(ip_range)
    devices= scan_network(ip_range)
    print(f"Dispositivi connessi: {len(devices)}\n")
    for i in range (0,len(devices)):
        print('-'*30)
        print(devices[i]['ip']+" | "+devices[i]['mac']+" | "+devices[i]['hostname']+ " | " + devices[i]['vendor'] )
        open_ports = scan_ports(devices[i]['ip'])
        if open_ports:
            print("Porte aperte rilevale: ")
            for p in open_ports:
                print(f" - Porta {p['port']}:{p['service']} - rischio {p['risk']}, {p['advice']} ")
                
        else:
            print("Nessuna porta comune aperta rilevata.")
    
            

    
    
    





if __name__ == "__main__":
    operazioni()
    
    
