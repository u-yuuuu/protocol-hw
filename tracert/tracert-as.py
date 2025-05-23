#!/usr/bin/python3
import socket
import struct
from enum import Enum
import re
import sys

class IcmpResponseType(Enum):
    TTL_EXCEEDED = 11
    ECHO_REPLY = 0
    TIMEOUT = -1
    OTHER = -2

def root(func):
    """Вызываем функцию с проверкой на наличие root"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError:
            print("Нужны права root")
            exit()
    return wrapper

def checksum(data):
    """Рассчитывает контрольную сумму ICMP пакета."""
    sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        sum += word
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += sum >> 16
    return ~sum & 0xFFFF

def reverse_dns_lookup(target):
    """Выполняет обратный DNS-запрос для IP-адреса."""
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        return hostname
    except socket.herror:
        return None

@root
def ping(ttl, target):
    """Отправляет echo запрос с указаным TTL на указаный адрес"""

    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    s.settimeout(2)
    
    icmp_type = 8 
    icmp_code = 0
    identifier = 12345  
    sequence = 1
    payload = b"abcdf"

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, sequence)
    packet = icmp_header + payload

    checksum_val = checksum(packet)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum_val, identifier, sequence)
    packet = header + payload

    s.sendto(packet, (target, 0))

    try:
        response, addr = s.recvfrom(1024)
        icmp_type = response[20]  # Тип ICMP (20-й байт в IP-заголовке)
        if icmp_type == 11:  
            return (IcmpResponseType.TTL_EXCEEDED, addr[0])
        if icmp_type == 0:
            return (IcmpResponseType.ECHO_REPLY, addr[0])
        return (IcmpResponseType.OTHER, addr[0])
    except socket.timeout:
       return (IcmpResponseType.TIMEOUT, None)
    finally:
        s.close()

def whois_query(target, server = "whois.iana.org", port = 43, timeout = 1):
    """Отправляет WHOIS-запрос к указанному серверу и возвращает ответ."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))

        s.send(f"{target}\r\n".encode())

        response=b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        return response.decode()
    except Exception as e:
        return f"Ошибка: {e}"
    finally:
        s.close()

def find_whois(ip_address, timeout=1):
    """Находит whois-сервер, ответственный за указанный IP-адрес"""
    current_server = "whois.iana.org"
    max_hops = 10  # защита от бесконечных циклов
    hop_count = 0
    
    while hop_count < max_hops:
        hop_count += 1
        try:
            response = whois_query(ip_address, current_server, timeout=timeout)
            
            # Проверяем, есть ли в ответе ссылка на следующий whois-сервер
            next_server = None
            for line in response.splitlines():
                if "whois:" in line.lower():
                    next_server = line.split(":")[1].strip()
                    break
                elif "refer:" in line.lower():
                    next_server = line.split(":")[1].strip()
                    break
            
            # Если следующего сервера нет - это конечный whois
            if not next_server:
                return (current_server, response)
            
            # Если следующий сервер совпадает с текущим - значит мы достигли конца
            if next_server.lower() == current_server.lower():
                return (current_server, response)
                
            current_server = next_server
            
        except Exception as e:
            return (None, f"Ошибка при поиске whois сервера: {e}")
    
    return (None, "Превышено максимальное количество переходов между whois-серверами")

def get_whois_netname(data):
    pattern = r"netname:\s*([A-Z0-9-]+)"
    matches = re.findall(pattern, data, re.IGNORECASE)
    try:
        return matches[-1] if matches else None
    except:
        return None

def get_whois_origin(data):
    pattern = r"origin:\s*([A-Z0-9]+)"
    matches = re.findall(pattern, data, re.IGNORECASE)
    try:
        return matches[-1] if matches else None
    except:
        return None

def get_whois_country(data):
    pattern = r"country:\s*([A-Z0-9]+)"
    matches = re.findall(pattern, data, re.IGNORECASE)
    try:
        return matches[-1] if matches else None
    except:
        return None

def parse_whois(data):
    netname = get_whois_netname(data)
    origin = get_whois_origin(data)
    country = get_whois_country(data)
    return (netname or "", origin or "", country or "")
    

if __name__ == "__main__":
    try:
        target = sys.argv[1]  
    except:
        print("tracert-as.py [target]")
        exit()

    for i in range(1, 256):
        response_type, ip_addr = ping(i, target)
        
        if not ip_addr:
            print(f"{i}. *\r")
            print("\r")
            print()
            continue
            
        hostname = reverse_dns_lookup(ip_addr)
        display_name = f"{hostname} ({ip_addr})" if hostname else ip_addr
        
        whois_server, whois_data = find_whois(ip_addr)
        if whois_server:
            whois_info = parse_whois(whois_query(ip_addr, whois_server))
        else:
            whois_info = (None, None, None)

        # Print in requested format
        print(f"{i}. {display_name}\r")
        whois_formatted = ", ".join(filter(str, whois_info))
        print(f"{whois_formatted}\r")
        print()

        if response_type == IcmpResponseType.ECHO_REPLY:
            break