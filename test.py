from pyids import Snort

# Create a Snort object
snort = Snort()

# Load Snort rules
snort.load_rules('/etc/snort/rules/local.rules')

# Create a test packet (replace with your own packet)
packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02\x00\x14\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x10\xff\xff\x3e\x00\x00\x00'

# Send the packet through Snort and get the alert (if any)
alert = snort.analyze_packet(packet)

if alert:
    print(f'Alert: {alert}')
else:
    print('No alert')
