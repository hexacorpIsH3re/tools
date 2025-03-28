## Want a custom code? Contact me on Discord!
## Discord: vapeclientt___



import requests, json, os, time, sys, socket
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
import nmap
import urllib.parse
import base64
from dhooks import Webhook
import morse_talk as morse
import gtts
from playsound import playsound
from pygame import mixer
import pygame


init()

def limpiar():
    
    os.system('cls' if os.name == 'nt' else 'clear')

def print_slow(str):
    for char in str:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.001)

def banner_login():
    ancho = os.get_terminal_size().columns
    frames = [
        Fore.RED + """
    ╔════════════════════════════════════════════════════════════╗
    ║                     H3XA TOOLS v1.0                        ║
    ╚════════════════════════════════════════════════════════════╝""" + Style.RESET_ALL,
        
        Fore.LIGHTRED_EX + """
    ╔════════════════════════════════════════════════════════════╗
    ║                     H3XA TOOLS v1.0                        ║
    ╚════════════════════════════════════════════════════════════╝""" + Style.RESET_ALL
    ]
    
    for _ in range(3):  
        for frame in frames:
            limpiar()
            print(frame.center(ancho))
            time.sleep(0.2)

def panel_tools():
    limpiar()
    print(Fore.RED + """
    https://github.com/hexacorpIsH3re/tools

    [I] Info                                              Next [N]
    [S] Site
    ├─────────────── H3XA TOOLS v1.0 ──────────────────────────┤
    │                                                           │
    ├ [01] Spam Webhook Discord    ├  [04] Base64 Decoder       │
    ├ [02] Texto a Morse           ├  [05] Texto a Voz          │
    ├ [03] Validar IP              │                            │
    └───────────────────────────── ┴─ ──────────────────────────┘
    """ + Style.RESET_ALL)

def login():
    limpiar()
    banner_login()
    
    print(Fore.RED + "\n[!] Sistema de Login | H3xa Tools" + Style.RESET_ALL)
    print("═" * 60)
    
    intentos = 3
    while intentos > 0:
        usuario = input(Fore.RED + "\n[>] Usuario: " + Style.RESET_ALL)
        password = input(Fore.RED + "[>] Password: " + Style.RESET_ALL)
        
        if usuario == "hexa" and password == "Admin":
            print(Fore.GREEN + "\n[+] Login exitoso! Bienvenido" + Style.RESET_ALL)
            time.sleep(1)
            return True
        else:
            intentos -= 1
            print(Fore.RED + f"\n[-] Login fallido. Intentos restantes: {intentos}" + Style.RESET_ALL)
            time.sleep(1)
            limpiar()
            banner_login()
    
    print(Fore.RED + "\n[!] Demasiados intentos fallidos. Saliendo..." + Style.RESET_ALL)
    return False

def loading_animation():
    chars = "/—\\|"
    for char in chars:
        sys.stdout.write('\r' + Fore.RED + f'[{char}] Iniciando H3xa Tools...' + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.2)

def website_vulnerability_scan(url):
    limpiar()
    print(Fore.RED + "[+] Escaneando vulnerabilidades en " + url + Style.RESET_ALL)
    try:
        response = requests.get(url)
        headers = response.headers
        
        print("\n[*] Verificando Headers de Seguridad:")
        security_headers = {
            'X-XSS-Protection': 'Protección XSS',
            'X-Content-Type-Options': 'Content Type Options',
            'X-Frame-Options': 'Frame Options',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP'
        }
        
        for header, desc in security_headers.items():
            if header in headers:
                print(Fore.GREEN + f"[✓] {desc}: Presente" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[✗] {desc}: Ausente - Vulnerabilidad Potencial" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def website_info_scan(url):
    limpiar()
    print(Fore.RED + "[+] Obteniendo información de " + url + Style.RESET_ALL)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        print("\n[*] Información básica:")
        print(f"[+] Título: {soup.title.string if soup.title else 'No encontrado'}")
        print(f"[+] Server: {response.headers.get('Server', 'No encontrado')}")
        print(f"[+] Tecnologías: {response.headers.get('X-Powered-By', 'No detectado')}")
        print(f"[+] Cookies: {len(response.cookies)} encontradas")
        
        print("\n[*] Meta tags:")
        for meta in soup.find_all('meta'):
            if meta.get('name'):
                print(f"[+] {meta.get('name')}: {meta.get('content')}")
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def url_scanner(url):
    limpiar()
    print(Fore.RED + "[+] Analizando URL: " + url + Style.RESET_ALL)
    try:
        parsed = urllib.parse.urlparse(url)
        print("\n[*] Componentes de la URL:")
        print(f"[+] Esquema: {parsed.scheme}")
        print(f"[+] Dominio: {parsed.netloc}")
        print(f"[+] Ruta: {parsed.path}")
        print(f"[+] Parámetros: {parsed.params}")
        print(f"[+] Query: {parsed.query}")
        
        ip = socket.gethostbyname(parsed.netloc)
        print(f"[+] IP asociada: {ip}")
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def port_scanner(target):
    limpiar()
    print(Fore.RED + "[+] Escaneando puertos en " + target + Style.RESET_ALL)
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '21-80')
        
        for host in nm.all_hosts():
            print(f"\n[*] Host: {host}")
            for proto in nm[host].all_protocols():
                print(f"[*] Protocolo: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"[+] Puerto {port}: {state}")
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def sql_scanner(url):
    limpiar()
    print(Fore.RED + "[+] Escaneando vulnerabilidades SQL en " + url + Style.RESET_ALL)
    payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users", "1 UNION SELECT 1,2,3"]
    
    try:
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url)
            
            if "SQL" in response.text or "mysql" in response.text.lower():
                print(Fore.RED + f"[!] Posible vulnerabilidad SQL encontrada con: {payload}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f"[✓] Prueba pasada: {payload}" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def xss_scanner(url):
    limpiar()
    print(Fore.RED + "[+] Escaneando vulnerabilidades XSS en " + url + Style.RESET_ALL)
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    try:
        for payload in payloads:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url)
            
            if payload in response.text:
                print(Fore.RED + f"[!] Posible vulnerabilidad XSS encontrada con: {payload}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f"[✓] Prueba pasada: {payload}" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def spam_webhook():
    limpiar()
    print(Fore.RED + "[+] Spam Webhook Discord" + Style.RESET_ALL)
    webhook_url = input(Fore.RED + "[>] Ingrese URL del Webhook: " + Style.RESET_ALL)
    mensaje = input(Fore.RED + "[>] Mensaje a enviar: " + Style.RESET_ALL)
    cantidad = int(input(Fore.RED + "[>] Cantidad de mensajes: " + Style.RESET_ALL))
    
    try:
        hook = Webhook(webhook_url)
        for i in range(cantidad):
            hook.send(f"{mensaje}")
            print(Fore.GREEN + f"[+] Mensajeenviado exitosamente" + Style.RESET_ALL)
            time.sleep(0.5)  
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def texto_morse():
    limpiar()
    print(Fore.RED + "[+] Convertidor Texto a Morse" + Style.RESET_ALL)
    texto = input(Fore.RED + "[>] Ingrese texto: " + Style.RESET_ALL)
    
    try:
        morse_code = morse.encode(texto)
        print(Fore.GREEN + "\n[+] Código Morse:" + Style.RESET_ALL)
        print(morse_code)
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)

def validar_ip():
    limpiar()
    print(Fore.RED + "[+] Validador de IP" + Style.RESET_ALL)
    ip = input(Fore.RED + "[>] Ingrese IP: " + Style.RESET_ALL)
    
    try:
        partes = ip.split('.')
        if len(partes) != 4:
            raise ValueError("IP inválida")
            
        for parte in partes:
            if not 0 <= int(parte) <= 255:
                raise ValueError("IP inválida")
                
        print(Fore.GREEN + f"\n[+] La IP {ip} es válida" + Style.RESET_ALL)
        
        
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        if response.status_code == 200:
            data = response.json()
            print(f"\n[*] País: {data.get('country_name', 'N/A')}")
            print(f"[*] Ciudad: {data.get('city', 'N/A')}")
            print(f"[*] ISP: {data.get('org', 'N/A')}")
            
    except Exception as e:
        print(Fore.RED + f"[!] Error: IP inválida" + Style.RESET_ALL)

def base64_decoder():
    limpiar()
    print(Fore.RED + "[+] Decodificador Base64" + Style.RESET_ALL)
    texto = input(Fore.RED + "[>] Ingrese texto en Base64: " + Style.RESET_ALL)
    
    try:
        decoded = base64.b64decode(texto).decode('utf-8')
        print(Fore.GREEN + "\n[+] Texto decodificado:" + Style.RESET_ALL)
        print(decoded)
    except Exception as e:
        print(Fore.RED + f"[!] Error: Texto Base64 inválido" + Style.RESET_ALL)

def texto_voz():
    limpiar()
    print(Fore.RED + "[+] Convertidor de Texto a Voz" + Style.RESET_ALL)
    texto = input(Fore.RED + "[>] Ingrese texto: " + Style.RESET_ALL)
    idioma = input(Fore.RED + "[>] Idioma (es/en/fr/etc): " + Style.RESET_ALL)
    
    try:
        
        pygame.init()
        mixer.init()
        
        
        tts = gtts.gTTS(text=texto, lang=idioma)
        archivo = "speech.mp3"
        tts.save(archivo)
        
        print(Fore.GREEN + "\n[+] Reproduciendo audio..." + Style.RESET_ALL)
        
        
        mixer.music.load(archivo)
        mixer.music.play()
        
        
        while mixer.music.get_busy():
            time.sleep(0.1)
            
        
        mixer.quit()
        os.remove(archivo)
        
    except Exception as e:
        print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL)
        if os.path.exists(archivo):
            os.remove(archivo)

def mostrar_info():
    limpiar()
    print(Fore.RED + """
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
    **********###########%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%########***********    
    *******##########%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%########*******    
    *****#########%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#######*****    
    ***#######%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%#####***    
    **######%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#####**    
    *#####%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#####    
    #####%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%##******#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%####    
    ####%@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%#******************+*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%##    
    ##%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#***********##**###******#%%%%%%%%%%##%%%%%%%%%@@@@@@@@%%#    
    ##%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*******####****####******###########%%%######%%@@@@@@@@@%#    
    #%%@@@@@@@@@@@@@@@@@@@@@@@%%#####**************#********************###%%%%%%%%%%%%%%%%%@@@%    
    #%@@@@@%%%%%%%%%%%######********************########***##***########***#%@@@@@@@@@@@@@@@@@@@    
    #%@@@@@@@@@@@@%%%%%%###***#########********###########*###***#########**##%%%@@@@@@@@@@@@@@@    
    #%@@@@@@@@@@@@@@@@%##***############******############*##****#****######**###**#%%%%@@@@@@@@    
    #%@@@@@@@@@@@@@@@%#***#######****###*****################***#*#####**#####***#######%%#%%@%%    
    #%@@@@@@@@@@%%###***######*****************###########****#####**###*######****##%%%%@@@@%%%    
    #%@@@@@@@@@@@%%##****######**********###******#######**#########*****#########***#%%%%%%@@@@    
    #%@@@@@@@@@@@@@@%****######*********##############*#########*****############***##%%%@@@@@%%    
    #%@@@@@@@@@@@@@@@#***#######*******###########***########*******############***#%@@@@@@@@@@@    
    #%@@@@@@@@@@@@%%##***#######****##***#######*#######*********####***########**#%@@@@@@@@@@@@    
    #%@@@@@@@@@@@@@%%#****#######***######*#*##**********##############*#######***#%%%%%@@@@@@@@    
    #%@@@@@@@@@@@@@@@%#**####*******###########***#####################***####***#%%%%%%%@@@@@@@    
    #%@@@@@@@@@@@@@@@@##************##########*########################*####***#####%%####%@@@%@    
    #%@@@@@@@@@@@@@@%#*****###******#########*################################*##%@@@@@@@@@@@@@@    
    #%@@@@@@@@@@@%#*****##########***######################################**#*##@@@@@@@@@@@@@@@    
    #%@%@@@@@@@@%#****###########*****#######*######################**######**#*##@@@@@@@@@@@@@@    
    #%@@@@@@@@@@@@#***##########********####**####################***########*****####%%@@@@@@@@    
    #%@@@@@@@@@@@@@%#**#########*********###*************#######***##*#######******##%%%%%%%%%%%    
    #%@@@@@@@@@@@@@@%#**#########*****************###########****######*######******#%%%@@@@@@@@    
    #%@@@@@@@@%%%##%%##**#########*******########################*#####*#######****#%@@@@@@@@@@@    
    #%@@@@@%%%%%%@@@@%%#****#########****#############################**####*****##%@@@@@@@@@@@@    
    #%@@@@@@@@@@@@@@@@@%%##****#########**###########################**########%%%@@@@@%%%%%%%%%    
    #%@@@@%%@@@@@@@@@%%##%%%#**##****##################*****++******########=+%@@@@%%@@@@@@@@@@@    
    #%@@@@@@@@@@@@@@@@@@@@@@#+=##**######*##*=+#****%%%%%###+-+*######%%###%#+-#@@@@%%@%###%%%%%    
    #%@@%@@@@@@@@@@@@@@@@@%#=+######*******+-+%@@@@%%%@@@%%%%#**+++****###%%%#+=#@@%%##%@@@@@@@@    
    #%%@@@@@@@@@@@@@@@@@@@#+*#%####*++++=--+#@@@@@@%%%%%###%%%@@%%#+=-=+*##%%%*=+#%%#*#%%%@@@@%%    
    #%%@@@@@@@@@@@@@@@@@@%#=###*++====+*#%%%@@@@@@@@@@@@@@@@@@@@@@@@@@%*===*###*++@@@@@@@@@@@@@%    
    ##%%@@@@@@@@@@@@@@@@@@#-++=*#%%@@%@@@%@%%%@@@@@%%%%%@@@@@@@@@@@@@@@@@@%#=+*+++@@@@@@@@@@@@%#    
    ####%@@@@@@@@@@@@@@@@@#:-+%@@@@@@%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*-:+%@@@@%#**%@@%##    
    ####%%@@@@@@@@@@@@@@@@%*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-+@@@@@@%%@@@%%##    
    #####%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%####    
    #######%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#####    
    #########%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#######    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    

    ╔════════════════════════════════════════════════════════════╗
    ║                    H3XA TOOLS TEAM                         ║
    ╠════════════════════════════════════════════════════════════╣
    ║ [+] Alex/Cord1    -  Pentester & Exploit Developer        ║
    ║ [+] sparkles/akacc - Advanced Malware Analyst & Reverser  ║
    ║ [+] Adressito/exploit - Security Researcher & Developer   ║
    ║ [+] Fran/Fran;v - Malware Encrypter & Java developer      ║
    ╚════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    input("\nPresione Enter para continuar...")

def main():
    if login():
        print("\n")
        for _ in range(3):
            loading_animation()
        
        while True:
            panel_tools()
            opcion = input(Fore.RED + "\n[hexa@tools]─[~]$ " + Style.RESET_ALL)
            
            if opcion.lower() == 'exit':
                print(Fore.RED + "\n[!] Saliendo de H3xa Tools..." + Style.RESET_ALL)
                break
            elif opcion.lower() == 'cls':
                continue
            elif opcion.lower() == 'n':
                print(Fore.RED + "\n[!] Este modulo esta en desarrollo..." + Style.RESET_ALL)
                input("\nPresione Enter para continuar...")
            elif opcion.lower() == 's':
                print(Fore.GREEN + "\n[+] discord.gg/hexacorp" + Style.RESET_ALL)
                input("\nPresione Enter para continuar...")
            elif opcion.lower() == 'i':
                mostrar_info()
            elif opcion == "01":
                spam_webhook()
                input("\nPresione Enter para continuar...")
            elif opcion == "02":
                texto_morse()
                input("\nPresione Enter para continuar...")
            elif opcion == "03":
                validar_ip()
                input("\nPresione Enter para continuar...")
            elif opcion == "04":
                base64_decoder()
                input("\nPresione Enter para continuar...")
            elif opcion == "05":
                texto_voz()
                input("\nPresione Enter para continuar...")
            else:
                print(Fore.RED + "\n[!] Opcion invalida..." + Style.RESET_ALL)
                time.sleep(1)

if __name__ == "__main__":
    main()
