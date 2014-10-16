"""
setup:

apt-get install python3-pip
pip install IPy
python3 sslcheck.py 10.0.1.0/24

jcmurphy@buffalo.edu
"""
import socket, ssl, pprint, sys, IPy, getopt
port = 443

def help(m=""):
	print("sslv3check.py -n <network/mask> [-t]")
	print("   -t check if SSLv3 is enabled and TLSv1 is not enabled")
	print("      otherwise just see if SSLv3 is enabled")
	print(m)
	sys.exit(2)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hn:t")
	except getopt.GetoptError:
		help()

	network = None
	no_tlsv1 = False

	for opt, arg in opts:
		if opt == '-h':
			help()
		elif opt == '-n':
			network = arg
		elif opt == '-t':
			no_tlsv1 = True
	
	if network == None:
		help("-n required")

	ip = IPy.IP(network)
	for x in ip:
		if ip.prefixlen() != 32 and (ip.broadcast() == x or ip.net() == x):
			continue
		sslv3 = check_sslv3(x, port)
		if no_tlsv1 == True:
			tlsv1 = check_tls(x, port)
			if sslv3 == "enabled" and tlsv1 != "enabled":
				print("{0} SSLv3 enabled and TLSv1 not enabled".format(str(x)))
			elif sslv3 == "enabled" and tlsv1 == "enabled":
				print("{0} SSLv3 enabled and TLSv1 enabled".format(str(x)))
			else:
				print("{0} SSLv3={1} TLSv1={2}".format(str(x), sslv3, tlsv1))
		else:
			if sslv3 == "enabled":
				print("{0} SSLv3 enabled".format(str(x)))
			else:
				print("{0} SSLv3 {1}".format(str(x), sslv3))


def check_tls(h, p):
	return check(h, p, ssl.PROTOCOL_TLSv1)

def check_sslv3(h, p):
	return check(h, p, ssl.PROTOCOL_SSLv3)

def check(h, p, ctx):
	context = ssl.SSLContext(ctx)
	context.verify_mode = ssl.CERT_NONE
	context.check_hostname = False
	context.load_default_certs()

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		ssl_sock = context.wrap_socket(s, server_hostname=str(h), do_handshake_on_connect=True)
		ssl_sock.connect((str(h), p))
		ssl_sock.close()
		return "enabled"
	except Exception as e:
		return str(e)

if __name__ == "__main__":
	main()
