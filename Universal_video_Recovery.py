#!/usr/bin/env python3
"""
Universal Video Recovery from PCAP
Automatically detects and extracts different video formats
"""

from scapy.all import *
import os
import sys
import subprocess
import re

class VideoExtractor:
    def __init__(self, pcap_file, output_dir='frames', output_video='recovered_video.mp4', fps=25):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.output_video = output_video
        self.fps = fps
        self.packets = None
        self.stream_type = None
        self.stream_info = {}
        
    def analyze_pcap(self):
        """Step 1: Read PCAP and identify what kind of video stream it contains"""
        print(f"[*] Reading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
            return False
        
        print(f"[*] Total packets: {len(self.packets)}")
        print("[*] Analyzing stream type...")
        
        # Counters for different stream types
        stream_types = {
            'mjpeg': 0,
            'rtsp': 0,
            'rtp': 0,
            'http_mp4': 0,
            'http_flv': 0,
            'http_other': 0,
            'raw_h264': 0,
            'raw_h265': 0
        }
        
        # Analyze first 100 packets with data
        analyzed = 0
        for pkt in self.packets:
            if analyzed > 100:
                break
                
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                # Check for MJPEG (multipart/x-mixed-replace)
                if b'multipart/x-mixed-replace' in payload or b'image/jpeg' in payload:
                    stream_types['mjpeg'] += 10
                    if not self.stream_info.get('mjpeg'):
                        self.stream_info['mjpeg'] = {
                            'src': pkt[IP].src,
                            'sport': pkt[TCP].sport,
                            'dst': pkt[IP].dst,
                            'dport': pkt[TCP].dport
                        }
                
                # Check for HTTP video (MP4, FLV, etc.)
                if b'Content-Type: video/' in payload:
                    if b'video/mp4' in payload:
                        stream_types['http_mp4'] += 10
                    elif b'video/x-flv' in payload:
                        stream_types['http_flv'] += 10
                    else:
                        stream_types['http_other'] += 5
                    
                    if not self.stream_info.get('http_video'):
                        self.stream_info['http_video'] = {
                            'src': pkt[IP].src,
                            'sport': pkt[TCP].sport,
                            'dst': pkt[IP].dst,
                            'dport': pkt[TCP].dport
                        }
                
                # Check for RTSP
                if b'RTSP/' in payload or b'rtsp://' in payload.lower():
                    stream_types['rtsp'] += 10
                
                # Check for H.264 NAL units (00 00 00 01 or 00 00 01)
                if b'\x00\x00\x00\x01' in payload or b'\x00\x00\x01' in payload[:100]:
                    stream_types['raw_h264'] += 1
                
                # Check for H.265 NAL units
                if b'\x00\x00\x00\x01\x40' in payload or b'\x00\x00\x00\x01\x42' in payload:
                    stream_types['raw_h265'] += 1
                
                analyzed += 1
            
            # Check for RTP (UDP packets)
            elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                # RTP has specific header structure
                if len(payload) > 12:
                    # Check RTP version (should be 2)
                    version = (payload[0] >> 6) & 0x3
                    if version == 2:
                        stream_types['rtp'] += 1
                analyzed += 1
        
        # Determine the most likely stream type
        max_score = max(stream_types.values())
        if max_score == 0:
            print("[!] Could not identify video stream type!")
            print("[*] Stream analysis:")
            for stype, score in stream_types.items():
                print(f"    {stype}: {score}")
            return False
        
        for stype, score in stream_types.items():
            if score == max_score:
                self.stream_type = stype
                break
        
        print(f"[+] Detected stream type: {self.stream_type.upper()}")
        print(f"[*] Confidence scores:")
        for stype, score in sorted(stream_types.items(), key=lambda x: x[1], reverse=True):
            if score > 0:
                print(f"    {stype}: {score}")
        
        return True
    
    def extract_mjpeg(self):
        """Extract MJPEG stream (individual JPEG frames)"""
        print("[*] Extracting MJPEG stream...")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Collect stream data
        stream_data = b''
        stream_info = self.stream_info.get('mjpeg')
        
        if not stream_info:
            # Try to find it again
            for pkt in self.packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if b'multipart' in payload or b'image/jpeg' in payload:
                        stream_info = {
                            'src': pkt[IP].src,
                            'sport': pkt[TCP].sport,
                            'dst': pkt[IP].dst,
                            'dport': pkt[TCP].dport
                        }
                        break
        
        if stream_info:
            print(f"[*] Stream: {stream_info['src']}:{stream_info['sport']} -> {stream_info['dst']}:{stream_info['dport']}")
        
        # Collect all packets
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if stream_info:
                    if (pkt[IP].src == stream_info['src'] and 
                        pkt[TCP].sport == stream_info['sport']):
                        stream_data += bytes(pkt[Raw].load)
                else:
                    # If we couldn't identify stream, collect all TCP data
                    stream_data += bytes(pkt[Raw].load)
        
        print(f"[*] Collected {len(stream_data):,} bytes")
        
        # Extract JPEG frames
        frame_count = 0
        pos = 0
        
        while pos < len(stream_data):
            jpeg_start = stream_data.find(b'\xff\xd8', pos)
            if jpeg_start == -1:
                break
            
            jpeg_end = stream_data.find(b'\xff\xd9', jpeg_start)
            if jpeg_end == -1:
                break
            
            jpeg_data = stream_data[jpeg_start:jpeg_end + 2]
            
            if len(jpeg_data) > 1000:  # Valid frame
                frame_file = f"{self.output_dir}/frame_{frame_count:05d}.jpg"
                with open(frame_file, 'wb') as f:
                    f.write(jpeg_data)
                frame_count += 1
                if frame_count % 10 == 0:
                    print(f"[*] Extracted {frame_count} frames...", end='\r')
            
            pos = jpeg_end + 2
        
        print(f"\n[+] Extracted {frame_count} JPEG frames")
        return frame_count
    
    def extract_http_video(self):
        """Extract complete video file from HTTP stream (MP4, FLV, etc.)"""
        print("[*] Extracting HTTP video stream...")
        
        stream_info = self.stream_info.get('http_video')
        video_data = b''
        in_body = False
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                # Skip HTTP headers
                if not in_body:
                    header_end = payload.find(b'\r\n\r\n')
                    if header_end != -1:
                        payload = payload[header_end + 4:]
                        in_body = True
                    else:
                        continue
                
                if stream_info:
                    if (pkt[IP].src == stream_info['src'] and 
                        pkt[TCP].sport == stream_info['sport']):
                        video_data += payload
                else:
                    video_data += payload
        
        print(f"[*] Collected {len(video_data):,} bytes")
        
        # Detect file format from magic bytes
        if video_data.startswith(b'\x00\x00\x00'):
            # Likely MP4
            extension = 'mp4'
        elif video_data.startswith(b'FLV'):
            extension = 'flv'
        elif video_data.startswith(b'RIFF'):
            extension = 'avi'
        else:
            extension = 'bin'
        
        output_file = f"extracted_video.{extension}"
        with open(output_file, 'wb') as f:
            f.write(video_data)
        
        print(f"[+] Saved video as: {output_file}")
        
        # Try to convert/repair with ffmpeg
        try:
            print("[*] Converting with ffmpeg...")
            cmd = ['ffmpeg', '-i', output_file, '-c', 'copy', '-y', self.output_video]
            subprocess.run(cmd, capture_output=True, check=True)
            print(f"[+] Final video: {self.output_video}")
            return 1
        except:
            print(f"[!] Could not convert. Raw file saved as: {output_file}")
            return 0
    
    def extract_rtp(self):
        """Extract RTP video stream (often H.264)"""
        print("[*] Extracting RTP stream...")
        
        rtp_payloads = []
        
        for pkt in self.packets:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                if len(payload) > 12:
                    # Check if it's RTP (version 2)
                    version = (payload[0] >> 6) & 0x3
                    if version == 2:
                        # RTP header is 12 bytes minimum
                        rtp_payload = payload[12:]
                        rtp_payloads.append(rtp_payload)
        
        print(f"[*] Found {len(rtp_payloads)} RTP packets")
        
        # Combine payloads
        raw_stream = b''.join(rtp_payloads)
        
        # Save raw stream
        raw_file = 'rtp_stream.h264'
        with open(raw_file, 'wb') as f:
            f.write(raw_stream)
        
        print(f"[*] Saved raw RTP stream: {raw_file}")
        
        # Try to convert with ffmpeg
        try:
            print("[*] Converting to video...")
            cmd = ['ffmpeg', '-i', raw_file, '-c:v', 'copy', '-y', self.output_video]
            subprocess.run(cmd, capture_output=True, check=True)
            print(f"[+] Video saved: {self.output_video}")
            return 1
        except:
            print("[!] Could not convert RTP stream")
            return 0
    
    def extract_raw_h264(self):
        """Extract raw H.264 stream from TCP"""
        print("[*] Extracting raw H.264 stream...")
        
        h264_data = b''
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                # Look for H.264 NAL units
                if b'\x00\x00\x00\x01' in payload or b'\x00\x00\x01' in payload:
                    h264_data += payload
        
        print(f"[*] Collected {len(h264_data):,} bytes")
        
        raw_file = 'raw_stream.h264'
        with open(raw_file, 'wb') as f:
            f.write(h264_data)
        
        print(f"[*] Saved raw H.264: {raw_file}")
        
        # Try to convert
        try:
            print("[*] Converting to video...")
            cmd = ['ffmpeg', '-i', raw_file, '-c:v', 'copy', '-y', self.output_video]
            subprocess.run(cmd, capture_output=True, check=True)
            print(f"[+] Video saved: {self.output_video}")
            return 1
        except:
            print("[!] Could not convert. Try: ffmpeg -f h264 -i raw_stream.h264 output.mp4")
            return 0
    
    def frames_to_video(self, frame_count):
        """Convert extracted frames to video"""
        if frame_count == 0:
            return False
        
        print(f"[*] Converting {frame_count} frames to video at {self.fps} FPS...")
        
        cmd = [
            'ffmpeg',
            '-framerate', str(self.fps),
            '-i', f'{self.output_dir}/frame_%05d.jpg',
            '-c:v', 'libx264',
            '-pix_fmt', 'yuv420p',
            '-y',
            self.output_video
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Video saved: {self.output_video}")
                
                # Get duration
                try:
                    info_cmd = ['ffprobe', '-v', 'error', '-show_entries', 
                               'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1',
                               self.output_video]
                    duration = subprocess.run(info_cmd, capture_output=True, text=True)
                    if duration.returncode == 0:
                        print(f"[+] Duration: {float(duration.stdout.strip()):.2f} seconds")
                except:
                    pass
                return True
            else:
                print(f"[!] ffmpeg error: {result.stderr}")
                return False
        except FileNotFoundError:
            print("[!] ffmpeg not found. Install: sudo apt-get install ffmpeg")
            print(f"[*] Frames saved in: {self.output_dir}/")
            return False
    
    def extract(self):
        """Main extraction method - automatically chooses the right method"""
        if not self.analyze_pcap():
            return False
        
        print(f"\n{'='*60}")
        print(f"Extracting {self.stream_type.upper()} stream")
        print(f"{'='*60}\n")
        
        frame_count = 0
        
        if self.stream_type == 'mjpeg':
            frame_count = self.extract_mjpeg()
            if frame_count > 0:
                self.frames_to_video(frame_count)
        
        elif self.stream_type in ['http_mp4', 'http_flv', 'http_other']:
            self.extract_http_video()
        
        elif self.stream_type == 'rtp':
            self.extract_rtp()
        
        elif self.stream_type in ['raw_h264', 'raw_h265']:
            self.extract_raw_h264()
        
        else:
            print(f"[!] No extraction method for: {self.stream_type}")
            return False
        
        return True


def main():
    print("="*60)
    print("Universal Video Recovery from PCAP")
    print("Automatically detects: MJPEG, MP4, FLV, RTP, H.264")
    print("="*60)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python3 universal_extract.py <pcap_file> [fps] [output_video]")
        print("Example: python3 universal_extract.py capture.pcap 25 video.mp4")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    fps = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    output_video = sys.argv[3] if len(sys.argv) > 3 else 'recovered_video.mp4'
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: {pcap_file} not found!")
        sys.exit(1)
    
    extractor = VideoExtractor(pcap_file, fps=fps, output_video=output_video)
    
    if extractor.extract():
        print("\n" + "="*60)
        print("[+] Extraction complete!")
        print("="*60)
    else:
        print("\n[!] Extraction failed!")
        print("[*] Try manually checking the PCAP with Wireshark")


if __name__ == "__main__":
    main()
