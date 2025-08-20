from collections import defaultdict
import time
import threading
from dataclasses import dataclass
from typing import Dict, Set, List
import socket
from flask import request, abort
import logging
import queue
from threading import Lock
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
import signal
import json
import sqlite3
from datetime import datetime

@dataclass
class ConnectionInfo:
    request_count: int = 0
    last_request_time: float = 0
    blocked_until: float = 0
    request_queue: queue.Queue = None
    syn_count: int = 0
    last_syn_time: float = 0
    total_requests: int = 0
    last_minute_requests: int = 0
    last_minute_time: float = 0
    half_open_count: int = 0
    last_half_open_cleanup: float = 0
    last_reset_time: float = 0
    burst_count: int = 0

    def __post_init__(self):
        self.request_queue = queue.Queue(maxsize=2000)
        self.last_reset_time = time.time()

class DDoSProtection:
    def __init__(self):
        # Initialize logging first
        self._init_monitoring()
        
        # Protection thresholds with more aggressive defaults
        self.RATE_LIMIT_SECONDS = 0.1  # More aggressive rate limiting
        self.MAX_REQUESTS_PER_SECOND = 20  # More restrictive request limit
        self.MAX_REQUESTS_PER_MINUTE = 500  # More restrictive per-minute limit
        self.BLOCK_DURATION = 3600  # 1 hour block duration
        self.BURST_THRESHOLD = 10  # Lower burst threshold
        self.BURST_WINDOW = 0.1  # Shorter burst window
        
        # Connection limits with tighter restrictions
        self.MAX_CONNECTIONS_GLOBAL = 1000  # Lower global connection limit
        self.MAX_CONNECTIONS_PER_IP = 20  # Lower per-IP connection limit
        self.MAX_HALF_OPEN_CONNECTIONS = 50  # Lower half-open connection limit
        self.HALF_OPEN_CLEANUP_INTERVAL = 0.2  # More frequent cleanup
        
        # Attack detection thresholds
        self.ATTACK_DETECTION_WINDOW = 1  # Shorter detection window
        self.ATTACK_REQUEST_THRESHOLD = 100  # Lower request threshold
        self.ATTACK_SYN_THRESHOLD = 50  # Lower SYN threshold
        
        # Resource management
        self.MAX_TRACKED_IPS = 2000  # Lower number of tracked IPs
        self.IP_CLEANUP_THRESHOLD = 1500  # Lower cleanup threshold
        self.MEMORY_CHECK_INTERVAL = 15  # More frequent memory checks
        self.MAX_MEMORY_PERCENT = 60  # Lower memory threshold
        
        # IP tracking with LRU mechanism
        self.ip_tracker: Dict[str, ConnectionInfo] = defaultdict(ConnectionInfo)
        self.ip_last_seen: Dict[str, float] = {}
        self.half_open_connections: Dict[str, Set[int]] = defaultdict(set)
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = {'127.0.0.1', 'localhost'}
        self.lock = Lock()
        
        # Database setup
        self._init_database()
        
        # Protection state
        self.protection_enabled = self._load_protection_state()
        self.under_attack = False
        self.attack_start_time = 0
        self.attack_type = None
        self.last_attack_check = time.time()
        self.last_memory_check = time.time()
        
        # Rate limiting buckets
        self.rate_limit_buckets: Dict[str, List[float]] = defaultdict(list)
        self.bucket_lock = Lock()
        
        # Start monitoring threads
        self._start_monitoring_threads()

    def _init_database(self):
        """Initialize SQLite database for persistent storage."""
        try:
            with sqlite3.connect('ddos_protection.db') as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS protection_state (
                        id INTEGER PRIMARY KEY,
                        enabled INTEGER NOT NULL,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip TEXT PRIMARY KEY,
                        blocked_until TIMESTAMP,
                        reason TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")

    def _load_protection_state(self) -> bool:
        """Load protection state from database."""
        try:
            with sqlite3.connect('ddos_protection.db') as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT enabled FROM protection_state 
                    ORDER BY last_updated DESC LIMIT 1
                """)
                result = cursor.fetchone()
                return bool(result[0]) if result else True
        except Exception as e:
            self.logger.error(f"Error loading protection state: {str(e)}")
            return True  # Default to enabled on error

    def _save_protection_state(self, enabled: bool):
        """Save protection state to database."""
        try:
            with sqlite3.connect('ddos_protection.db') as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO protection_state (enabled, last_updated)
                    VALUES (?, CURRENT_TIMESTAMP)
                """, (int(enabled),))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error saving protection state: {str(e)}")
            raise

    def _init_monitoring(self):
        """Initialize monitoring and logging with enhanced error handling."""
        try:
            log_dir = 'logs'
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Configure logging with rotation
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                os.path.join(log_dir, 'ddos_protection.log'),
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
            ))
            
            self.logger = logging.getLogger('ddos_protection')
            self.logger.setLevel(logging.INFO)
            self.logger.addHandler(handler)
            
        except Exception as e:
            print(f"Error initializing monitoring: {str(e)}")  # Fallback if logging fails
            raise

    def _start_monitoring_threads(self):
        """Start monitoring threads."""
        try:
            # Start monitoring threads
            for target, name in [
                (self._attack_detection_loop, 'AttackDetector'),
                (self._cleanup_loop, 'CleanupLoop'),
                (self._adaptive_threshold_loop, 'AdaptiveThreshold')
            ]:
                thread = threading.Thread(target=target, daemon=True, name=name)
                thread.start()
            
            self.logger.info(f"DDoS protection initialized and {'enabled' if self.protection_enabled else 'disabled'}")
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring threads: {str(e)}")

    def _check_memory_usage(self):
        """Check system memory usage and clean up if necessary."""
        try:
            import psutil
            current_time = time.time()
            
            if current_time - self.last_memory_check < self.MEMORY_CHECK_INTERVAL:
                return
                
            self.last_memory_check = current_time
            memory_percent = psutil.Process().memory_percent()
            
            if memory_percent > self.MAX_MEMORY_PERCENT:
                with self.lock:
                    # Clean up old IP entries
                    sorted_ips = sorted(
                        self.ip_last_seen.items(),
                        key=lambda x: x[1]
                    )
                    
                    # Remove oldest 25% of IPs
                    ips_to_remove = sorted_ips[:len(sorted_ips) // 4]
                    for ip, _ in ips_to_remove:
                        if ip not in self.blacklist and ip not in self.whitelist:
                            del self.ip_tracker[ip]
                            del self.ip_last_seen[ip]
                            if ip in self.half_open_connections:
                                del self.half_open_connections[ip]
                    
                    # Force garbage collection
                    import gc
                    gc.collect()
                    
        except ImportError:
            pass  # psutil not available
        except Exception as e:
            self.logger.error(f"Memory check error: {str(e)}")

    def _cleanup_old_entries(self):
        """Clean up old IP entries to prevent memory exhaustion."""
        try:
            current_time = time.time()
            with self.lock:
                # Clean IP tracker
                for ip in list(self.ip_tracker.keys()):
                    info = self.ip_tracker[ip]
                    if (current_time - info.last_request_time > 300 and  # 5 minutes
                        current_time - info.last_syn_time > 300 and
                        ip not in self.blacklist and
                        ip not in self.whitelist):
                        del self.ip_tracker[ip]
                        if ip in self.ip_last_seen:
                            del self.ip_last_seen[ip]
                
                # Clean rate limit buckets
                with self.bucket_lock:
                    for ip in list(self.rate_limit_buckets.keys()):
                        self.rate_limit_buckets[ip] = [
                            t for t in self.rate_limit_buckets[ip]
                            if current_time - t <= self.RATE_LIMIT_SECONDS
                        ]
                        if not self.rate_limit_buckets[ip]:
                            del self.rate_limit_buckets[ip]
                
                # Clean half-open connections
                for ip in list(self.half_open_connections.keys()):
                    if not self.half_open_connections[ip]:
                        del self.half_open_connections[ip]
                
                # Clean blacklist
                self.blacklist = {
                    ip for ip in self.blacklist
                    if ip in self.ip_tracker and
                    self.ip_tracker[ip].blocked_until > current_time
                }
                
        except Exception as e:
            self.logger.error(f"Cleanup error: {str(e)}")

    def _rate_limit_request(self, ip: str) -> bool:
        """Rate limit requests using token bucket algorithm."""
        try:
            current_time = time.time()
            
            with self.bucket_lock:
                # Clean old requests
                self.rate_limit_buckets[ip] = [
                    t for t in self.rate_limit_buckets[ip]
                    if current_time - t <= self.RATE_LIMIT_SECONDS
                ]
                
                # Check rate limit
                if len(self.rate_limit_buckets[ip]) >= self.MAX_REQUESTS_PER_SECOND:
                    return False
                
                # Add new request
                self.rate_limit_buckets[ip].append(current_time)
                return True
                
        except Exception as e:
            self.logger.error(f"Rate limiting error: {str(e)}")
            return True  # Allow on error

    def _check_attack_conditions(self):
        """Check for attack conditions and update attack state."""
        current_time = time.time()
        window_start = current_time - self.ATTACK_DETECTION_WINDOW

        with self.lock:
            # Count requests and SYNs in the window
            total_requests = sum(
                info.request_count 
                for info in self.ip_tracker.values() 
                if info.last_request_time >= window_start
            )
            total_syns = sum(
                info.syn_count 
                for info in self.ip_tracker.values() 
                if info.last_syn_time >= window_start
            )
            
            # Detect attack type
            if total_requests > self.ATTACK_REQUEST_THRESHOLD:
                return "http_flood"
            elif total_syns > self.ATTACK_SYN_THRESHOLD:
                return "syn_flood"
            
            return None

    def _handle_attack_detection(self, attack_type):
        """Handle detected attack."""
        with self.lock:
            if not self.under_attack or self.attack_type != attack_type:
                self.under_attack = True
                self.attack_start_time = time.time()
                self.attack_type = attack_type
                self.logger.warning(f"Attack detected! Type: {attack_type}. Enabling strict protection measures")
                
                # Adjust limits based on attack type
                if attack_type == "http_flood":
                    self.MAX_REQUESTS_PER_SECOND = 50
                    self.MAX_REQUESTS_PER_MINUTE = 1000
                    self.BURST_THRESHOLD = 20
                elif attack_type == "syn_flood":
                    self.MAX_CONNECTIONS_PER_IP = 50
                    self.MAX_HALF_OPEN_CONNECTIONS = 100
                
                # Block IPs that exceed thresholds
                current_time = time.time()
                for ip, info in self.ip_tracker.items():
                    if (info.request_count > self.MAX_REQUESTS_PER_SECOND or
                        info.half_open_count > self.MAX_HALF_OPEN_CONNECTIONS):
                        self.blacklist.add(ip)
                        info.blocked_until = current_time + self.BLOCK_DURATION
                        self._save_blocked_ip(ip, info.blocked_until, attack_type)

    def _save_blocked_ip(self, ip: str, blocked_until: float, reason: str):
        """Save blocked IP to database."""
        try:
            with sqlite3.connect('ddos_protection.db') as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO blocked_ips (ip, blocked_until, reason)
                    VALUES (?, ?, ?)
                """, (ip, blocked_until, reason))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error saving blocked IP: {str(e)}")

    def _attack_detection_loop(self):
        """Continuously monitor for attack patterns."""
        while True:
            try:
                if self.protection_enabled:
                    attack_type = self._check_attack_conditions()
                    
                    if attack_type:
                        self._handle_attack_detection(attack_type)
                    elif self.under_attack:
                        # Check if attack has subsided
                        current_time = time.time()
                        if current_time - self.attack_start_time > 60:  # Check after 1 minute
                            if not self._check_attack_conditions():
                                self.under_attack = False
                                self.attack_type = None
                                self._restore_normal_limits()
                                self.logger.info("Attack has subsided, restoring normal operations")
                
                time.sleep(1)  # Check every second
            except Exception as e:
                self.logger.error(f"Attack detection error: {str(e)}")
                time.sleep(1)

    def _restore_normal_limits(self):
        """Restore normal operation limits after attack."""
        self.MAX_REQUESTS_PER_SECOND = 200
        self.MAX_REQUESTS_PER_MINUTE = 3000
        self.MAX_CONNECTIONS_PER_IP = 200
        self.BURST_THRESHOLD = 50
        self.MAX_HALF_OPEN_CONNECTIONS = 500

    def check_http_flood(self, ip: str) -> bool:
        """Check for HTTP flood attacks with enhanced protection."""
        if not self.protection_enabled or ip in self.whitelist:
            return True
            
        current_time = time.time()
        
        try:
            # Update last seen time
            self.ip_last_seen[ip] = current_time
            
            # Check memory usage periodically
            self._check_memory_usage()
            
            with self.lock:
                info = self.ip_tracker[ip]
                
                # Check blacklist with immediate effect
                if ip in self.blacklist:
                    if current_time < info.blocked_until:
                        return False
                    self.blacklist.remove(ip)
                
                # Implement token bucket algorithm for rate limiting
                bucket_key = f"{ip}_tokens"
                if not hasattr(info, bucket_key):
                    setattr(info, bucket_key, self.MAX_REQUESTS_PER_SECOND)
                    setattr(info, f"{bucket_key}_last_update", current_time)
                
                # Refill tokens
                last_update = getattr(info, f"{bucket_key}_last_update")
                time_passed = current_time - last_update
                tokens = getattr(info, bucket_key)
                tokens = min(
                    self.MAX_REQUESTS_PER_SECOND,
                    tokens + time_passed * (self.MAX_REQUESTS_PER_SECOND / self.RATE_LIMIT_SECONDS)
                )
                
                if tokens < 1:
                    info.request_count += 1
                    if info.request_count > self.MAX_REQUESTS_PER_SECOND:
                        self.blacklist.add(ip)
                        info.blocked_until = current_time + self.BLOCK_DURATION
                        self._save_blocked_ip(ip, info.blocked_until, "rate_limit_exceeded")
                        return False
                    return False
                
                # Consume a token
                tokens -= 1
                setattr(info, bucket_key, tokens)
                setattr(info, f"{bucket_key}_last_update", current_time)
                
                # Update request counts
                info.total_requests += 1
                info.last_minute_requests += 1
                info.burst_count += 1
                
                # Reset counters if needed
                if current_time - info.last_reset_time >= 60:
                    info.last_minute_requests = 0
                    info.burst_count = 0
                    info.last_reset_time = current_time
                
                # Check minute-based limit
                if info.last_minute_requests > self.MAX_REQUESTS_PER_MINUTE:
                    self.blacklist.add(ip)
                    info.blocked_until = current_time + self.BLOCK_DURATION
                    self._save_blocked_ip(ip, info.blocked_until, "http_flood")
                    return False
                
                # Check burst limit with shorter window
                if (current_time - info.last_reset_time <= self.BURST_WINDOW and
                    info.burst_count > self.BURST_THRESHOLD):
                    self.blacklist.add(ip)
                    info.blocked_until = current_time + self.BLOCK_DURATION
                    self._save_blocked_ip(ip, info.blocked_until, "burst_attack")
                    return False
                
                info.last_request_time = current_time
                return True
                
        except Exception as e:
            self.logger.error(f"Error in HTTP flood check: {str(e)}")
            return False  # Block on error to be safe

    def check_tcp_syn_flood(self, ip: str, port: int) -> bool:
        """Enhanced TCP SYN flood detection."""
        if not self.protection_enabled:
            return True

        if ip in self.whitelist:
            return True

        current_time = time.time()
        
        with self.lock:
            if ip in self.blacklist:
                return False

            info = self.ip_tracker[ip]
            
            # Update SYN count
            info.syn_count += 1
            info.last_syn_time = current_time
            
            # Check for rapid SYN requests
            if info.syn_count > self.ATTACK_SYN_THRESHOLD:
                time_diff = current_time - info.last_reset_time
                if time_diff < self.ATTACK_DETECTION_WINDOW:
                    # SYN flood detected
                    self.blacklist.add(ip)
                    self._handle_attack_detection("TCP_SYN_FLOOD")
                    self._save_blocked_ip(ip, current_time + self.BLOCK_DURATION, "TCP SYN flood detected")
                    self.logger.warning(f"TCP SYN flood detected from {ip}. IP blocked for {self.BLOCK_DURATION} seconds.")
                    return False
                else:
                    # Reset counters if window expired
                    info.syn_count = 1
                    info.last_reset_time = current_time
            
            # Track half-open connections
            if ip in self.half_open_connections:
                if len(self.half_open_connections[ip]) >= self.MAX_HALF_OPEN_CONNECTIONS:
                    self.blacklist.add(ip)
                    self._handle_attack_detection("HALF_OPEN_FLOOD")
                    self._save_blocked_ip(ip, current_time + self.BLOCK_DURATION, "Too many half-open connections")
                    self.logger.warning(f"Too many half-open connections from {ip}. IP blocked.")
                    return False
                self.half_open_connections[ip].add(port)
            else:
                self.half_open_connections[ip] = {port}
            
            # Cleanup old half-open connections
            if current_time - info.last_half_open_cleanup > self.HALF_OPEN_CLEANUP_INTERVAL:
                self.half_open_connections[ip] = set()
                info.last_half_open_cleanup = current_time
            
            return True

    def connection_established(self, ip: str, port: int):
        """Handle established connections."""
        with self.lock:
            if ip in self.half_open_connections:
                self.half_open_connections[ip].discard(port)
                if ip in self.ip_tracker:
                    self.ip_tracker[ip].half_open_count = len(self.half_open_connections[ip])

    def _cleanup_loop(self):
        """Clean up expired entries more frequently."""
        while True:
            try:
                current_time = time.time()
                with self.lock:
                    # Clean IP tracker more aggressively
                    for ip in list(self.ip_tracker.keys()):
                        info = self.ip_tracker[ip]
                        if (current_time - info.last_request_time > 60 and  # Reduced from 300
                            current_time - info.last_syn_time > 60 and
                            ip not in self.blacklist):
                            del self.ip_tracker[ip]
                            if ip in self.ip_last_seen:
                                del self.ip_last_seen[ip]
                    
                    # Clean half-open connections more frequently
                    for ip in list(self.half_open_connections.keys()):
                        if current_time - self.ip_tracker[ip].last_syn_time > 30:  # 30 seconds timeout
                            del self.half_open_connections[ip]
                    
                    # Clean blacklist
                    self.blacklist = {
                        ip for ip in self.blacklist
                        if ip in self.ip_tracker and
                        self.ip_tracker[ip].blocked_until > current_time
                    }
                
                time.sleep(5)  # Clean every 5 seconds instead of 10
            except Exception as e:
                self.logger.error(f"Cleanup error: {str(e)}")

    def get_protection_stats(self) -> dict:
        """Get protection statistics."""
        try:
            with self.lock:
                current_time = time.time()
                active_connections = sum(len(conns) for conns in self.half_open_connections.values())
                total_requests = sum(info.total_requests for info in self.ip_tracker.values())
                
                return {
                    'protection_enabled': self.protection_enabled,
                    'under_attack': self.under_attack,
                    'attack_type': self.attack_type,
                    'tracked_ips': len(self.ip_tracker),
                    'blocked_ips': len(self.blacklist),
                    'half_open_connections': active_connections,
                    'blacklisted_ips': list(self.blacklist),
                    'total_requests': total_requests,
                    'requests_per_second': sum(
                        1 for info in self.ip_tracker.values()
                        if current_time - info.last_request_time <= 1
                    ),
                    'max_requests_per_second': self.MAX_REQUESTS_PER_SECOND,
                    'max_connections_per_ip': self.MAX_CONNECTIONS_PER_IP
                }
        except Exception as e:
            self.logger.error(f"Error getting protection stats: {str(e)}")
            return {
                'protection_enabled': self.protection_enabled,
                'under_attack': self.under_attack,
                'attack_type': self.attack_type,
                'error': str(e)
            }

    def toggle_protection(self) -> bool:
        """Toggle DDoS protection on/off and persist the state."""
        try:
            with self.lock:
                # Toggle the state
                self.protection_enabled = not self.protection_enabled
                
                # Save the new state to the database
                self._save_protection_state(self.protection_enabled)
                
                # Reset counters and clear blacklist if disabling protection
                if not self.protection_enabled:
                    self.blacklist.clear()
                    self.ip_tracker.clear()
                    self.half_open_connections.clear()
                    self.under_attack = False
                    self.attack_type = None
                    self._restore_normal_limits()
                
                self.logger.info(f"DDoS protection {'enabled' if self.protection_enabled else 'disabled'}")
                return self.protection_enabled
                
        except Exception as e:
            self.logger.error(f"Error toggling protection: {str(e)}")
            # Don't change state if there was an error
            return self.protection_enabled

    def is_protected(self) -> bool:
        """Check if protection is enabled."""
        return self.protection_enabled

    def _adaptive_threshold_loop(self):
        """Adaptively adjust thresholds based on traffic patterns and system load."""
        while True:
            try:
                current_time = time.time()
                
                # Get system metrics
                import psutil
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.Process().memory_percent()
                
                # Adjust thresholds based on system load
                if cpu_percent > 80 or memory_percent > 80:
                    self.MAX_REQUESTS_PER_SECOND = max(20, self.MAX_REQUESTS_PER_SECOND * 0.5)
                    self.MAX_CONNECTIONS_PER_IP = max(20, self.MAX_CONNECTIONS_PER_IP * 0.5)
                    self.BURST_THRESHOLD = max(10, self.BURST_THRESHOLD * 0.5)
                elif self.under_attack:
                    self.MAX_REQUESTS_PER_SECOND = max(50, self.MAX_REQUESTS_PER_SECOND * 0.8)
                    self.MAX_CONNECTIONS_PER_IP = max(50, self.MAX_CONNECTIONS_PER_IP * 0.8)
                    self.BURST_THRESHOLD = max(20, self.BURST_THRESHOLD * 0.8)
                else:
                    self.MAX_REQUESTS_PER_SECOND = min(100, self.MAX_REQUESTS_PER_SECOND * 1.1)
                    self.MAX_CONNECTIONS_PER_IP = min(100, self.MAX_CONNECTIONS_PER_IP * 1.1)
                    self.BURST_THRESHOLD = min(30, self.BURST_THRESHOLD * 1.1)
                
                time.sleep(5)  # Adjust every 5 seconds
                
            except ImportError:
                time.sleep(5)  # psutil not available
            except Exception as e:
                self.logger.error(f"Error in adaptive threshold loop: {str(e)}")
                time.sleep(5)

# Create global instance
ddos_protection = DDoSProtection() 