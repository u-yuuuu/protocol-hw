#!/bin/python3
import argparse
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

def root(func):
    """Вызываем функцию с проверкой на наличие root"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError:
            print("Нужны права root")
            exit()
    return wrapper

def ntp_time(unix_ts):
    ntp_epoch = 2208988800  
    ntp_ts = unix_ts + ntp_epoch
    seconds = int(ntp_ts)
    fraction = int((ntp_ts - seconds) * 0x100000000)  # 2^32
    return seconds, fraction

def generate_sntp_response(data, delay):
    if len(data) < 48:
        return None
    # Достаем версию и режим клиента
    client_first_byte = data[0]
    client_vn = (client_first_byte >> 3) & 0x07
    client_mode = client_first_byte & 0x07

    if client_mode != 3:  # Ответ не от клиента
        return None

    # Достаем поле transit
    originate = data[40:48]

    # Считаем делей до клиента
    t_recv_real = time.time()
    t_xmit_real = time.time()
    t_recv = t_recv_real + delay
    t_xmit = t_xmit_real + delay

    # в NTP
    ref_seconds, ref_fraction = ntp_time(t_xmit)
    recv_seconds, recv_fraction = ntp_time(t_recv)
    xmit_seconds, xmit_fraction = ntp_time(t_xmit)

    packet = bytearray(48)
    packet[0] = (0 << 6) | (client_vn << 3) | 4
    packet[1] = 1  
    packet[2] = 0  
    packet[3] = 0  
    packet[4:12] = b'\x00' * 8
    packet[12:16] = b'LOCL'
    struct.pack_into('!II', packet, 16, ref_seconds, ref_fraction)
    packet[24:32] = originate
    struct.pack_into('!II', packet, 32, recv_seconds, recv_fraction)
    struct.pack_into('!II', packet, 40, xmit_seconds, xmit_fraction)

    return bytes(packet)

def handle_request(sock, data, addr, delay):
    response = generate_sntp_response(data, delay)
    if response:
        sock.sendto(response, addr)

@root
def main():
    parser = argparse.ArgumentParser(description='Deceptive SNTP Server')
    parser.add_argument('-d', '--delay', type=int, default=0, help='Time offset in seconds')
    parser.add_argument('-p', '--port', type=int, default=123, help='Port to listen on')
    args = parser.parse_args()

    print(f"Starting SNTP server with delay {args.delay} on port {args.port}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('', args.port))
        with ThreadPoolExecutor() as executor:
            while True:
                data, addr = sock.recvfrom(1024)
                print(addr[0])
                executor.submit(handle_request, sock, data, addr, args.delay)

if __name__ == '__main__':
    main()