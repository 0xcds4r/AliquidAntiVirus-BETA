import os
import hashlib
from concurrent.futures import ThreadPoolExecutor
import keyboard
from rich import print
import time
import threading

class AliquidVirusScanner:
	def __init__(self, directory):
		self.directory = directory
		self.malicious_hashes = None
		self.malicious_founded = []
		
		with open('virushashes.txt', 'r') as f:
			self.malicious_hashes = f.read()
	
	def check_file(self, file_path):
		try:
			with open(file_path, 'rb') as f:
				file_hash = hashlib.md5(f.read()).hexdigest()
			
			if file_hash in self.malicious_hashes:
				print(f"[red][Warning] File {file_path} is malicious (hash: {file_hash})[/]")
				self.malicious_founded.append((file_path, file_hash))
			else:
				print(f"[green][INFO] File {file_path} is clean (hash: {file_hash})[/]")
		except (PermissionError, FileNotFoundError):
			pass
	
	def scan_directory(self):
		with ThreadPoolExecutor() as executor:
			for root, dirs, files in os.walk(self.directory):
				for file in files:
					file_path = os.path.join(root, file)
					executor.submit(self.check_file, file_path)

	def get_malicious_founded(self):
		return self.malicious_founded

print("Aliquid Virus Scanner | version: 1.0 | by 0xcds4r")
print("This solution will help you scan your files for malware")

scan_path = input("Write scan path (ex. 'C:\\\\') -> ")
print("Loading.. (Please wait)")
if len(scan_path) > 0:
	global scanner
	scanner = AliquidVirusScanner(scan_path)

	start_scan = input(f"Start scan path: {scan_path} ? (1 - YES / 0 - NO) -> ")

	if "1" in start_scan:
		scanner.scan_directory()

	malicious_files = scanner.get_malicious_founded()

	if len(malicious_files) > 0:
		print(f"Malicious files found: {malicious_files}")
		for file_path, file_hash in malicious_files:
			action = input(f"Malicious file found: {file_path}. What do you want to do? (1 - delete, 2 - quarantine, 3 - ignore, 4 - delete all) -> ")
			if action == "1":
				os.remove(file_path)
				print(f"[red][INFO] File {file_path} deleted[/]")
			elif action == "2":
				quarantine_path = os.path.join("C:\\", "aliquid_quarantine")
				if not os.path.exists(quarantine_path):
					os.makedirs(quarantine_path)
				new_file_path = os.path.join(quarantine_path, os.path.basename(file_path))
				os.rename(file_path, new_file_path)
				print(f"[yellow][INFO] File {file_path} moved to quarantine ({new_file_path})[/]")
			elif action == "3":
				print(f"[green][INFO] File {file_path} ignored[/]")
			elif action == "4":
				for file_path, file_hash in malicious_files:
					os.remove(file_path)
					print(f"[red][INFO] File {file_path} deleted[/]")
				break
	else:
		print("No malicious files found.")

		