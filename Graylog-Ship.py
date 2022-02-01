#!/usr/bin/python3

from scapy.all import *
import threading
import subprocess
import sys
import random
import time

class beacFrame:
	
	def __init__(self, essid, bssid, ts, interval, oui):
		self.essid = essid
		self.bssid = bssid
		self.ts = ts
		self.interval = interval
		self.oui = oui


	def __str__(self):
		return "ESSID:{}, BSSID:{}, Timestamp:{}, Beacon Interval:{}, Vendor OUI:{}".format(self.essid, self.bssid, self.ts, self.interval, self.oui)

class authFrame:
	def __init__(self, essid, bssid, ts, oui):
		self.essid = essid
		self.bssid = bssid
		self.ts = ts
		self.oui = oui


	def __str__(self):
		return "ESSID:{}, BSSID:{}, Timestamp:{}, Vendor OUI:{}".format(self.essid, self.bssid, self.ts, self.oui)

def isMonitor():
	interfaces = get_if_list()
	winter = sys.argv[1]
	
	if winter not in interfaces:
		print("'{}' is not an interface. Please set interface in arg 1.".format(winter))
		time.sleep(2)
		exit()
	

	print("Checking for monitor mode...")
	time.sleep(2)


	result = subprocess.run(["iwconfig", winter], stdout=subprocess.PIPE, text=True)
	
	if "Mode:Monitor" in result.stdout:
		print("{} is in monitor mode.".format(sys.argv[1]))
		time.sleep(2)
		return True
	
	else:
		print("{} is not in monitor mode.".format(sys.argv[1]))
		return False

def setMonitor():
	print("Setting up monitor mode")
	time.sleep(2)
	subprocess.run(["ifconfig", sys.argv[1], "down"])	
	subprocess.run(["iwconfig", sys.argv[1], "mode", "monitor"])
	subprocess.run(["ifconfig", sys.argv[1], "up"])	
	print("Done")
	time.sleep(2)
	

def channelHop():
	while True:
		channel = str(random.randint(1,11))
		result = subprocess.run(["iwconfig", sys.argv[1], "channel", channel])

def bf(frame):
	# The setup
	dotElt = frame.getlayer(Dot11Elt)
	dot11 = frame.getlayer(Dot11)
	dotbeacon = frame.getlayer(Dot11Beacon)
	vendor = frame.getlayer(Dot11EltVendorSpecific)

	# Pull the values
	essid = dotElt.info.decode("utf-8")
	bssid = dot11.addr2
	ts = dotbeacon.timestamp
	interval = dotbeacon.beacon_interval
	oui = vendor.oui

	# Make sure we skip the essids with null bytes
	if not all((ord(i) > 30) and (ord(i) < 128) for i in essid):
		return

	# Inappropriate essid removed from list
	if bssid == "00:5f:67:9c:3c:a8":
		return
	
	# Assign as object becuase why not
	bF = beacFrame(essid, bssid, ts, interval, oui)
	
	print(bF)

def authf(frame):
	dotElt = frame.getlayer(Dot11Elt)
	dot11 = frame.getlayer(Dot11)
	dotbeacon = frame.getlayer(Dot11Beacon)
	vendor = frame.getlayer(Dot11EltVendorSpecific)

	# Pull the values
	essid = dotElt.info.decode("utf-8")
	bssid = dot11.addr2
	ts = dotbeacon.timestamp
	interval = dotbeacon.beacon_interval
	oui = vendor.oui

	# Make sure we skip the essids with null bytes
	if not all((ord(i) > 30) and (ord(i) < 128) for i in essid):
		return

	# Inappropriate essid removed from list
	if bssid == "00:5f:67:9c:3c:a8":
		return
	
	# Assign as object becuase why not
	authF = authFrame(essid, bssid, ts, oui)
	
	print(authF)

def frameParse(frame):
	# If the frame is a beacon frame (has the beacon layer)

	# Need to add both association and authentication requests/responses
	# Dot11AssoReq
	# Dot11AssoResp
	# Dott11Auth
	# For all frame types, determine the signal strength and include it
	if frame.haslayer(Dot11Beacon):
		pass
		#bf(frame)
	if frame.haslayer(Dot11Auth):

def countdown():
	print("I will begin scanning in...")
	time.sleep(1)
	print("3")
	time.sleep(1)
	print("2")
	time.sleep(1)
	print("1")
	time.sleep(1)



def main():
	# If interface is not in monitor mode, set it to monitor mode.
	if not isMonitor():
		setMonitor()

	# Threading seen in video. Added basic randomInt function.	
	thread = threading.Thread(target=channelHop, name="ChannelHopper")
	thread.daemon = True
	thread.start()
	
	# Countdown for dramatic effect and to see what was just displayed before the stream of data.
	countdown()

	# Begin to sniff 802.11 frames	
	sniff(iface=sys.argv[1],prn=frameParse,store=0)
	
	
	


if __name__ == "__main__":
	main()
