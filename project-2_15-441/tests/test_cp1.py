#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
#
# This file is part of the TCP in the Wild course project developed for the
# Computer Networks course (15-441/641) taught at Carnegie Mellon University.
#
# No part of the project may be copied and/or distributed without the express
# permission of the 15-441/641 course staff.

from pathlib import Path

from scapy.all import rdpcap
from fabric import Connection

from common import PCAP, CMUTCP, ACK_MASK, IP_ADDRS
from common import (
    CMUTCP,
    ACK_MASK,
    TIMEOUT,
    IFNAME,
    SYN_MASK,
    START_TESTING_SERVER_CMD,
    STOP_TESTING_SERVER_CMD,
    TESTING_HOST_IP,
    ip,
    udp,
)

from test_util import do_handshake
from scapy.all import sr1, Raw



def test_pcap_packets_max_size():
    """Basic test: Check packets are smaller than max size"""
    print("Running test_pcap_packets_max_size()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return
    for pkt in packets:
        if CMUTCP in pkt:
            if len(pkt[CMUTCP]) > 1400:
                print("Found packet with length greater than max size")
                print("Test Failed")
                return
    print("Test passed")


def test_pcap_acks():
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_pcap_acks()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return
    print("tested pcap acks")

    expected_acks = []
    ack_nums = []
    for pkt in packets:
        if CMUTCP in pkt:
            # Ignore handshake packets, should test in a different test.
            payload_len = pkt[CMUTCP].plen - pkt[CMUTCP].hlen
            # if pkt[CMUTCP].flags == 0:
            if payload_len > 0:
                expected_acks.append(pkt[CMUTCP].seq_num + payload_len)
            elif pkt[CMUTCP].flags == ACK_MASK:
                ack_nums.append(pkt[CMUTCP].ack_num)

    print("expected acks:", expected_acks)
    print("acks given:", ack_nums)
    # Probably not the best way to do this test!
    if set(expected_acks) == set(ack_nums):
        print("Test Passed")
    else:
        print("Test Failed")


# This will try to run the server and client code.
def test_run_server_client():
    """Basic test: Run server and client, and initiate the file transfer."""
    print("Running test_run_server_client()")

    # We are using `tmux` to run the server and client in the background.
    #
    # This might also help you debug your code if the test fails. You may call
    # `getchar()` in your code to pause the program at any point and then use
    # `tmux attach -t pytest_server` or `tmux attach -t pytest_client` to
    # attach to the relevant TMUX session and see the output.

    start_server_cmd = (
        "tmux new -s pytest_server -d /vagrant/project-2_15-441/server"
    )
    start_client_cmd = (
        "tmux new -s pytest_client -d /vagrant/project-2_15-441/client"
    )
    stop_server_cmd = "tmux kill-session -t pytest_server"
    stop_client_cmd = "tmux kill-session -t pytest_client"

    failed = False

    original_file = Path("/vagrant/project-2_15-441/src/cmu_tcp.c")
    received_file = Path("/tmp/file.c")

    received_file.unlink(missing_ok=True)

    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server_conn,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client_conn,
    ):
        try:
            server_conn.run(start_server_cmd)
            # server_conn.run("tmux has-session -t pytest_server")

            client_conn.run(start_client_cmd)
            # client_conn.run("tmux has-session -t pytest_client")

            # Exit when server finished receiving file.
            server_conn.run(
                "while tmux has-session -t pytest_server; do sleep 1; done",
                hide=True,
            )
        except Exception as e:
            failed = True

        try:
            client_conn.run("tmux has-session -t pytest_client", hide=True)
            print("stop client")
            client_conn.run(stop_client_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if client already shut down.
            pass
        try:
            server_conn.local("tmux has-session -t pytest_server", hide=True)
            print("stop server")
            server_conn.local(stop_server_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if server already shut down.
            pass
        if failed:
            print("Test failed: Error running server or client")
            return

        # Compare SHA256 hashes of the files.
        server_hash_result = server_conn.run(f"sha256sum {received_file}")
        client_hash_result = client_conn.run(f"sha256sum {original_file}")

        if not server_hash_result.ok or not client_hash_result.ok:
            print("Test failed: Error getting file hashes")
            return

        server_hash = server_hash_result.stdout.split()[0]
        client_hash = client_hash_result.stdout.split()[0]

        if server_hash != client_hash:
            print("Test failed: File hashes do not match")
            return

        print("Test passed")


def test_basic_reliable_data_transfer():
    """Basic test: Check that when you run server and client starter code
    that the input file equals the output file
    """
    # Can you think of how you can test this? Give it a try!
    print("Running test_run_server_client()")

    # We are using `tmux` to run the server and client in the background.
    #
    # This might also help you debug your code if the test fails. You may call
    # `getchar()` in your code to pause the program at any point and then use
    # `tmux attach -t pytest_server` or `tmux attach -t pytest_client` to
    # attach to the relevant TMUX session and see the output.

    start_server_cmd = (
        "tmux new -s pytest_server -d /vagrant/project-2_15-441/server"
    )
    start_client_cmd = (
        "tmux new -s pytest_client -d /vagrant/project-2_15-441/client"
    )
    tcset_cmd = (
        "sudo tcset $IFNAME --rate 10Mbps --delay 20ms --loss 0.1% --overwrite"
    )
    stop_server_cmd = "tmux kill-session -t pytest_server"
    stop_client_cmd = "tmux kill-session -t pytest_client"

    failed = False

    original_file = Path("/vagrant/project-2_15-441/src/cmu_tcp.c")
    received_file = Path("/tmp/file.c")

    received_file.unlink(missing_ok=True)

    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server_conn,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client_conn,
    ):
        try:
            server_conn.run(start_server_cmd)
            # server_conn.run("tmux has-session -t pytest_server")

            client_conn.run(start_client_cmd)
            # client_conn.run("tmux has-session -t pytest_client")

            # Exit when server finished receiving file.
            server_conn.run(
                "while tmux has-session -t pytest_server; do sleep 1; done",
                hide=True,
            )
        except Exception as e:
            failed = True

        try:
            client_conn.run("tmux has-session -t pytest_client", hide=True)
            print("stop client")
            client_conn.run(stop_client_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if client already shut down.
            pass
        try:
            server_conn.local("tmux has-session -t pytest_server", hide=True)
            print("stop server")
            server_conn.local(stop_server_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if server already shut down.
            pass
        if failed:
            print("Test failed: Error running server or client")
            return

        # Compare SHA256 hashes of the files.
        server_hash_result = server_conn.run(f"sha256sum {received_file}")
        client_hash_result = client_conn.run(f"sha256sum {original_file}")

        if not server_hash_result.ok or not client_hash_result.ok:
            print("Test failed: Error getting file hashes")
            return

        server_hash = server_hash_result.stdout.split()[0]
        client_hash = client_hash_result.stdout.split()[0]

        if server_hash != client_hash:
            print("Test failed: File hashes do not match")
            return

        print("Test passed")
    pass


def test_basic_retransmit():
    """Basic test: Check that when a packet is lost, it's retransmitted"""
    # Can you think of how you can test this? Give it a try!
    pass


START_TESTING_STILL_SERVER_CMD = (
    "tmux new -s pytest_server -d /vagrant/"
    "project-2_15-441/tests/testing_still_server"
)
MAX_NETWORK_BUFFER = 65535
payloads = ["pa", "pytest 1234567", "hey, how are ya?",
            "you are a lump of foul deformity!"]
def test_change_adv_win():
    """Basic test: Check that the server correctly updates its receive window
    when the server receives data, but the server application doesn't read it
    """
    with Connection(
        host=TESTING_HOST_IP,
        user="vagrant",
        connect_kwargs={"password": "vagrant"},
    ) as conn:
        try:
            conn.run(START_TESTING_STILL_SERVER_CMD)
            # conn.run("tmux has-session -t pytest_server")
            server_seq = do_handshake(conn)
            sent_bytes = 0
            for payload in payloads:
                print("Testing payload size " + str(len(payload)))
                data_pkt = (
                    ip /
                    udp /
                    CMUTCP(
                        plen=25 + len(payload),
                        seq_num=1001 + sent_bytes,
                        ack_num=server_seq + 1,
                        flags=ACK_MASK,
                    )
                    / Raw(load=payload)
                )
                server_ack_pkt = sr1(data_pkt, timeout=1000000, iface=IFNAME)
                data_fail = server_ack_pkt is None\
                    or server_ack_pkt[CMUTCP].flags != ACK_MASK\
                    or server_ack_pkt[CMUTCP].ack_num != 1001 + sent_bytes + len(payload)
                if (data_fail):
                    print(
                        "Listener (server) did not properly respond to data "
                        "packet."
                    )
                    print("Test Failed")
                    conn.run(STOP_TESTING_SERVER_CMD)
                    return
                sent_bytes += len(payload)

                adv_win = server_ack_pkt[CMUTCP].advertised_window
                print("windows:", adv_win, MAX_NETWORK_BUFFER - sent_bytes)
                if(adv_win != MAX_NETWORK_BUFFER - sent_bytes):
                    print("Listener (server) did not send a proper advertised"
                    "window")
                    conn.run(STOP_TESTING_SERVER_CMD)
                    return
        finally:
            try:
                conn.run(STOP_TESTING_SERVER_CMD)
            except Exception:
                # Ignore error here that may occur if server stopped.
                pass
        print("Test Passed")


if __name__ == "__main__":
    test_pcap_packets_max_size()
    test_pcap_acks()
    test_change_adv_win()
    test_run_server_client()

