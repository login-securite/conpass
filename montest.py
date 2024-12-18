from ldap3 import Server, Connection, ALL, SUBTREE, NTLM
import socket

# Paramètres de connexion LDAP
ldap_server_ip = "10.10.10.101"  # Remplacez par l'adresse IP connue d'un contrôleur de domaine
username = "hackn.lab\\Administrator"  # Nom d'utilisateur au format DOMAINE\utilisateur
password = "P4ssw0rd"  # Mot de passe


server = Server(ldap_server_ip, get_info=ALL)
conn = Connection(server, user=username, password=password, authentication=NTLM, auto_bind=True)

# Requête pour trouver les contrôleurs de domaine
base_dn = "CN=Sites,CN=Configuration,DC=hackn,DC=lab"  # Remplacez par votre base DN
search_filter = "(objectClass=server)"

conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=["dNSHostName"])

# Récupération des adresses IP
domain_controllers = []
for entry in conn.entries:
    dns_name = entry.dNSHostName.value
    if dns_name:
        try:
            ip_address = socket.gethostbyname(dns_name)
            domain_controllers.append({"hostname": dns_name, "ip": ip_address})
        except socket.gaierror:
            print(f"Impossible de résoudre l'adresse IP de {dns_name}")

# Affichage des résultats
for dc in domain_controllers:
    print(f"Hostname: {dc['hostname']}, IP: {dc['ip']}")