# Python-ARPattacker

### Description
The project use to run the ARP Attack in python.

### How to use?
```sh
	Parameter:

	-i --interface : The interface you want to posion.
	-t --target    : The IP you want to attack.
	-g --gateway   : The gateway IP in the posion network.
	-p --packets   : The number of packet you want to sniff. Default :100

	example: sudo python ARPAttacker.py -i en0 -t 192.168.1.3 -g 192.168.1.1 -p 100

	[*] Remember to set your forwarding mode first.
	[*] If your computer is MAC.You should need to run this command.
	[*] $:sudo sysctl -w net.inet.ip.forwarding=1
```
After that,you will get a pcap file which named by date in your folder.


### Version
1.0.0


License
----

MIT


**Free Software, Hell Yeah!**
