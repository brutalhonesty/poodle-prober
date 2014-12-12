"""
setup:

apt-get install python3-pip
pip install IPy
python3 sslcheck.py 10.0.1.0/24

jcmurphy@buffalo.edu
"""
import socket, ssl, pprint, sys, IPy, argparse, multiprocessing, csv, os

parser = argparse.ArgumentParser(description='Scan a netblock for SSLv3 enabled servers on port 443')
parser.add_argument('--port', '-p', nargs='*', default=["443"], help='port to connect to (default=443)')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--network', '-n', nargs='*', default=None, help='<network/args>')
group.add_argument('--input', '-i', default=None, help='input CSV file')
group.add_argument('--host', '-H', nargs='*', default=None, help='hostname')
parser.add_argument('--output', '-o', default=None, help='output CSV file')
parser.add_argument('--tls', '-t', action='store_true', default=False, help='check if SSLv3 is enabled and TLSv1 is not enabled\n otherwise just see if SSLv3 is enabled')
parser.add_argument('--parallel', '-P', action='store_true', default=False, help='Process netblocks in parallel')
parser.add_argument('--verbose', '-v', action='store_true', default=False, help='Enable verbosity of output to stdout.')


def _validate_input(input_file):
    input_file = os.path.abspath(input_file)
    if os.path.exists(input_file) is False:
        raise Exception('Input file does not exist.')
    return input_file


def _output_ips(results):
    with open('ips.txt', 'w') as file:
        for result in results:
            file.write(str(result['host']) + '\n')
        file.close()


def output_csv(tls_enabled, results, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        if tls_enabled:
            writer.writerow(['IP Address', 'Port', 'SSL', 'TLS'])
        else:
            writer.writerow(['IP Address', 'Port', 'SSL'])
        for result in results:
            if tls_enabled is False:
                writer.writerow([str(result['host']), result['port'], str(result['sslv3'])])
            elif result['sslv3'] == "enabled" and result['tlsv1'] != "enabled":
                writer.writerow([str(result['host']), result['port'], "enabled", "not enabled"])
            else:
                writer.writerow([str(result['host']), result['port'], str(result['sslv3']), str(result['tlsv1'])])
        csvfile.close()


def print_results(host, port, sslv3, tlsv1):
    if tlsv1 is None:
        print("{0}:{1} SSLv3 {2}".format(str(host), port, sslv3))
        return

    if sslv3 == "enabled" and tlsv1 != "enabled":
        print("{0}:{1} SSLv3 enabled and TLSv1 not enabled".format(str(host), port))
    else:
        print("{0}:{1} SSLv3={2} TLSv1={3}".format(str(host), port, sslv3, tlsv1))


def main():
    args = parser.parse_args()
    args = vars(args)

    ports = []
    for port in args["port"]:
        for port in port.split(','):
            ports.append(port)

    args["port"] = ports

    tlsv1 = None

    if args["host"] is not None:
        for host in args["host"]:
            for p in args["port"]:
                sslv3 = check_sslv3(host, p)
                if args["tls"] is True:
                    tlsv1 = check_tls(host, p)
                print_results(host, p, sslv3, tlsv1)
        return

    net = IPy.IPSet()
    if args['network']:
        for network in args['network']:
            net.add(IPy.IP(network))
    elif args['input']:
        input_file = _validate_input(args['input'])
        with open(input_file, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in reader:
                net.add(IPy.IP('\n'.join(row)))
    else:
        raise Exception('Missing network or input file.')

    if args["parallel"]:
        p = multiprocessing.Pool()
        q = multiprocessing.Queue()

        for ip in net:
            q.put((check_net, ip, args["port"], args["tls"], args["verbose"]))

        while True:
            items = q.get()
            func = items[0]
            args = items[1:]
            p.apply_async(func, args)
            if q.empty():
                p.close()
                p.join()
                break
    else:
        results = []
        for ip in net:
            checked_values = check_net(ip, args["port"], args["tls"], args["verbose"])
            results.append(checked_values)
        if args['output']:
            output_csv(args['tls'], results, args['output'])


def check_net(ip, ports, tls, is_verbose):
    for x in ip:
        # if ip.prefixlen() != 32 and (ip.broadcast() == x or ip.net() == x):
        #    return {'host': x, 'port': '443', 'sslv3': 'UNKNOWN', 'tlsv1': 'UNKNOWN'}
        for p in ports:
            tlsv1 = None
            sslv3 = check_sslv3(x, p)
            if tls is True:
                tlsv1 = check_tls(x, p)
            if is_verbose is True:
                print_results(x, p, sslv3, tlsv1)
            return {'host': x, 'port': p, 'sslv3': sslv3, 'tlsv1': tlsv1}


def check_tls(h, p):
    return check(h, p, ssl.PROTOCOL_TLSv1)


def check_sslv3(h, p):
    return check(h, p, ssl.PROTOCOL_SSLv3)


def check(h, p, ctx):
    context = ssl.SSLContext(ctx)
    context.verify_mode = ssl.CERT_NONE

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        ssl_sock = context.wrap_socket(s, server_hostname=str(h), do_handshake_on_connect=True)
        ssl_sock.connect((str(h), int(p)))
        ssl_sock.close()
        return "enabled"
    except Exception as e:
        return str(e)

if __name__ == "__main__":
        main()
