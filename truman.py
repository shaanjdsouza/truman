import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="truman",
        description="Truman network toolkit",
        epilog=(
            "Examples:\n"
            "  truman scan -t 192.168.1.0/24\n"
            "  truman trace -t 8.8.8.8"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local network with ARP requests",
        description="Find available devices on a local network.",
    )
    scan_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target network in CIDR notation, for example 192.168.1.0/24",
    )

    trace_parser = subparsers.add_parser(
        "trace",
        help="Trace ICMP packets to a target",
        description="Ping a target and count sent and received ICMP packets.",
    )
    trace_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target host or IP address, for example 8.8.8.8",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        from lan_scanner import main as scan_main

        scan_main(["-t", args.target])
    elif args.command == "trace":
        from packet_sniffer import main as trace_main

        trace_main(["-t", args.target])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
