#!/usr/bin/env python3
from scapy.all import *
import socket
import time
import sys
from decimal import Decimal

# usage:
# python3 pcap_send.py 235.10.10.134.50000.pcap 192.165.56.184 13000 --preserve-timing

def replay_pcap(pcap_file, target_ip, target_port, loop_count=-1, interval=1.0, preserve_timing=False):
    """
    Replay pcap file with loop and timing options
    loop_count: number of loops, -1 for infinite
    interval: seconds between loops
    preserve_timing: whether to preserve original packet timing
    """
    print(f"Reading pcap file: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets: {len(packets)}")
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
    print(f"UDP packets: {len(udp_packets)}")
    
    if not udp_packets:
        print("No UDP packets found!")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current_loop = 0
    
    # If preserving timing, calculate time reference
    if preserve_timing and udp_packets:
        print("Timing preservation: Enabled")
    else:
        print("Timing preservation: Disabled")
    
    try:
        while loop_count == -1 or current_loop < loop_count:
            current_loop += 1
            loop_type = "Infinite" if loop_count == -1 else f"{current_loop}/{loop_count}"
            print(f"\n=== Loop {current_loop} ({loop_type}) ===")
            print(f"Timing: {'Preserved' if preserve_timing else 'Fast replay'}")
            
            packet_count = 0
            start_time = time.time()
            loop_start_time = time.time()
            
            if preserve_timing and udp_packets:
                # Preserve original timing
                first_packet_time = float(udp_packets[0].time)  # Convert to float
                
                for i, packet in enumerate(udp_packets):
                    try:
                        udp_layer = packet[UDP]
                        
                        # Get payload
                        if hasattr(udp_layer, 'payload'):
                            if hasattr(udp_layer.payload, 'original'):
                                payload = udp_layer.payload.original
                            else:
                                payload = bytes(udp_layer.payload)
                        else:
                            continue
                        
                        # Convert packet time to float to avoid type errors
                        packet_time = float(packet.time)
                        time_since_first = packet_time - first_packet_time
                        
                        # If not first packet, wait for correct timing
                        if i > 0:
                            elapsed_real_time = time.time() - loop_start_time
                            wait_time = time_since_first - elapsed_real_time
                            
                            if wait_time > 0:
                                time.sleep(wait_time)
                        
                        # Send data
                        sock.sendto(payload, (target_ip, target_port))
                        packet_count += 1
                        
                        # Show progress every 100 packets
                        if (i + 1) % 100 == 0:
                            print(f"  Sent {i + 1}/{len(udp_packets)} packets")
                            
                    except Exception as e:
                        print(f"Error sending packet {i}: {e}")
                        continue
            else:
                # Fast sending mode (no timing preservation)
                for i, packet in enumerate(udp_packets):
                    try:
                        udp_layer = packet[UDP]
                        
                        # Get payload
                        if hasattr(udp_layer, 'payload'):
                            if hasattr(udp_layer.payload, 'original'):
                                payload = udp_layer.payload.original
                            else:
                                payload = bytes(udp_layer.payload)
                        else:
                            continue
                        
                        # Send data
                        sock.sendto(payload, (target_ip, target_port))
                        packet_count += 1
                        
                        # Small delay to avoid congestion (fast mode only)
                        if not preserve_timing and i % 100 == 0 and i > 0:
                            time.sleep(0.001)
                            
                        # Show progress every 100 packets
                        if (i + 1) % 100 == 0:
                            print(f"  Sent {i + 1}/{len(udp_packets)} packets")
                            
                    except Exception as e:
                        print(f"Error sending packet {i}: {e}")
                        continue
            
            end_time = time.time()
            duration = end_time - start_time
            packets_per_second = packet_count / duration if duration > 0 else 0
            
            print(f"Sent {packet_count} packets in {duration:.2f} seconds ({packets_per_second:.1f} pkt/s)")
            
            # Wait for interval if not last loop
            if loop_count == -1 or current_loop < loop_count:
                if interval > 0:
                    print(f"Waiting {interval:.1f} seconds before next loop...")
                    time.sleep(interval)
                else:
                    print("Proceeding to next loop immediately")
                    
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    except Exception as e:
        print(f"\n\nError: {e}")
    finally:
        sock.close()
        print(f"\nFinished. Total loops completed: {current_loop}")

# Alternative simpler version without timing preservation
def replay_pcap_simple(pcap_file, target_ip, target_port, loop_count=-1, interval=1.0):
    """
    Simple version without timing preservation - more reliable
    """
    print(f"Reading pcap file: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets: {len(packets)}")
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
    print(f"UDP packets: {len(udp_packets)}")
    
    if not udp_packets:
        print("No UDP packets found!")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current_loop = 0
    
    try:
        while loop_count == -1 or current_loop < loop_count:
            current_loop += 1
            loop_type = "Infinite" if loop_count == -1 else f"{current_loop}/{loop_count}"
            print(f"\n=== Loop {current_loop} ({loop_type}) ===")
            
            packet_count = 0
            start_time = time.time()
            
            for i, packet in enumerate(udp_packets):
                try:
                    udp_layer = packet[UDP]
                    
                    # Get payload
                    if hasattr(udp_layer, 'payload'):
                        if hasattr(udp_layer.payload, 'original'):
                            payload = udp_layer.payload.original
                        else:
                            payload = bytes(udp_layer.payload)
                    else:
                        continue
                    
                    # Send data
                    sock.sendto(payload, (target_ip, target_port))
                    packet_count += 1
                    
                    # Small delay every 100 packets to avoid congestion
                    if i % 100 == 0 and i > 0:
                        time.sleep(0.001)
                        
                    # Show progress every 100 packets
                    if (i + 1) % 100 == 0:
                        print(f"  Sent {i + 1}/{len(udp_packets)} packets")
                        
                except Exception as e:
                    print(f"Error sending packet {i}: {e}")
                    continue
            
            end_time = time.time()
            duration = end_time - start_time
            packets_per_second = packet_count / duration if duration > 0 else 0
            
            print(f"Sent {packet_count} packets in {duration:.2f} seconds ({packets_per_second:.1f} pkt/s)")
            
            # Wait for interval if not last loop
            if loop_count == -1 or current_loop < loop_count:
                if interval > 0:
                    print(f"Waiting {interval:.1f} seconds before next loop...")
                    time.sleep(interval)
                else:
                    print("Proceeding to next loop immediately")
                    
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    except Exception as e:
        print(f"\n\nError: {e}")
    finally:
        sock.close()
        print(f"\nFinished. Total loops completed: {current_loop}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='PCAP Replay Tool')
    parser.add_argument('pcap_file', help='Path to pcap file')
    parser.add_argument('target_ip', help='Destination IP address')
    parser.add_argument('target_port', type=int, help='Destination port')
    parser.add_argument('--loop-count', type=int, default=-1, 
                       help='Number of loops (-1 for infinite)')
    parser.add_argument('--interval', type=float, default=1.0,
                       help='Seconds between loops')
    parser.add_argument('--preserve-timing', action='store_true',
                       help='Preserve original packet timing')
    parser.add_argument('--simple', action='store_true',
                       help='Use simple mode (no timing preservation)')
    
    args = parser.parse_args()
    
    # ========== Display info ==========
    print("=== PCAP Replay Tool ===")
    print(f"Target: {args.target_ip}:{args.target_port}")
    print(f"Pcap file: {args.pcap_file}")
    print(f"Loop mode: {'Infinite' if args.loop_count == -1 else f'{args.loop_count} loops'}")
    print(f"Loop interval: {args.interval}s")
    print(f"Timing preservation: {'Enabled' if args.preserve_timing else 'Disabled'}")
    print("Press Ctrl+C to stop\n")
    
    # ========== Execute replay ==========
    if args.simple or not args.preserve_timing:
        replay_pcap_simple(
            pcap_file=args.pcap_file,
            target_ip=args.target_ip, 
            target_port=args.target_port,
            loop_count=args.loop_count,
            interval=args.interval
        )
    else:
        replay_pcap(
            pcap_file=args.pcap_file,
            target_ip=args.target_ip, 
            target_port=args.target_port,
            loop_count=args.loop_count,
            interval=args.interval,
            preserve_timing=args.preserve_timing
        )