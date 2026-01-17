#!/usr/bin/env python3
"""
Universal Video Recovery from PCAP - RTP Enhanced Version
"""

from scapy.all import *
import os
import sys
import subprocess
import struct

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
        
        # Analyze packets
        analyzed = 0
        for pkt in self.packets:
            if analyzed > 100:
                break
                
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                # Check for MJPEG
                if b'multipart/x-mixed-replace' in payload or b'image/jpeg' in payload:
                    stream_types['mjpeg'] += 10
                    if not self.stream_info.get('mjpeg'):
                        self.stream_info['mjpeg'] = {
                            'src': pkt[IP].src,
                            'sport': pkt[TCP].sport,
                            'dst': pkt[IP].dst,
                            'dport': pkt[TCP].dport
                        }
                
                # Check for HTTP video
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
                
                # Check for H.264 NAL units
                if b'\x00\x00\x00\x01' in payload or b'\x00\x00\x01' in payload[:100]:
                    stream_types['raw_h264'] += 1
                
                # Check for H.265 NAL units
                if b'\x00\x00\x00\x01\x40' in payload or b'\x00\x00\x00\x01\x42' in payload:
                    stream_types['raw_h265'] += 1
                
                analyzed += 1
            
            # Check for RTP (UDP packets)
            elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if len(payload) > 12:
                    # Check RTP version (should be 2)
                    version = (payload[0] >> 6) & 0x3
                    if version == 2:
                        stream_types['rtp'] += 1
                        
                        # Get RTP info
                        if not self.stream_info.get('rtp'):
                            self.stream_info['rtp'] = {
                                'src': pkt[IP].src,
                                'sport': pkt[UDP].sport,
                                'dst': pkt[IP].dst,
                                'dport': pkt[UDP].dport
                            }
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
            
            if len(jpeg_data) > 1000:
                frame_file = f"{self.output_dir}/frame_{frame_count:05d}.jpg"
                with open(frame_file, 'wb') as f:
                    f.write(jpeg_data)
                frame_count += 1
                if frame_count % 10 == 0:
                    print(f"[*] Extracted {frame_count} frames...", end='\r')
            
            pos = jpeg_end + 2
        
        print(f"\n[+] Extracted {frame_count} JPEG frames")
        return frame_count
    
    def extract_rtp_enhanced(self):
        """Enhanced RTP extraction with proper NAL unit reconstruction"""
        print("[*] Extracting RTP stream (enhanced)...")
        
        stream_info = self.stream_info.get('rtp')
        rtp_packets = []
        
        # Collect RTP packets
        for pkt in self.packets:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                if len(payload) > 12:
                    version = (payload[0] >> 6) & 0x3
                    if version == 2:
                        # Parse RTP header
                        header = payload[0]
                        padding = (header >> 5) & 0x1
                        extension = (header >> 4) & 0x1
                        csrc_count = header & 0x0F
                        
                        # Calculate header length
                        header_len = 12 + (csrc_count * 4)
                        
                        # Extract RTP payload
                        rtp_payload = payload[header_len:]
                        
                        # Get timestamp and sequence number
                        timestamp = struct.unpack('>I', payload[4:8])[0]
                        seq_num = struct.unpack('>H', payload[2:4])[0]
                        
                        rtp_packets.append({
                            'seq': seq_num,
                            'timestamp': timestamp,
                            'payload': rtp_payload
                        })
        
        print(f"[*] Found {len(rtp_packets)} RTP packets")
        
        if len(rtp_packets) == 0:
            print("[!] No RTP packets found!")
            return 0
        
        # Sort by sequence number
        rtp_packets.sort(key=lambda x: x['seq'])
        
        # Try different reconstruction methods
        methods = [
            ('raw', self._reconstruct_raw),
            ('h264_nal', self._reconstruct_h264_nal),
            ('fragmented', self._reconstruct_fragmented)
        ]
        
        for method_name, method_func in methods:
            print(f"[*] Trying reconstruction method: {method_name}")
            h264_data = method_func(rtp_packets)
            
            if len(h264_data) > 0:
                filename = f'rtp_stream_{method_name}.h264'
                with open(filename, 'wb') as f:
                    f.write(h264_data)
                
                print(f"[*] Saved {len(h264_data):,} bytes to: {filename}")
                
                # Try to convert with different ffmpeg options
                if self._try_convert_h264(filename, method_name):
                    return 1
        
        print("[!] All conversion methods failed")
        print("[*] Raw stream files saved. Try manual conversion:")
        print("    ffmpeg -f h264 -i rtp_stream_raw.h264 -c:v copy output.mp4")
        return 0
    
    def _reconstruct_raw(self, rtp_packets):
        """Method 1: Simple concatenation of payloads"""
        return b''.join([p['payload'] for p in rtp_packets])
    
    def _reconstruct_h264_nal(self, rtp_packets):
        """Method 2: Add NAL start codes"""
        h264_data = b''
        nal_start_code = b'\x00\x00\x00\x01'
        
        for pkt in rtp_packets:
            payload = pkt['payload']
            if len(payload) > 0:
                # Check if it already has start code
                if not payload.startswith(b'\x00\x00\x00\x01') and not payload.startswith(b'\x00\x00\x01'):
                    h264_data += nal_start_code
                h264_data += payload
        
        return h264_data
    
    def _reconstruct_fragmented(self, rtp_packets):
        """Method 3: Handle fragmented NAL units (FU-A)"""
        h264_data = b''
        nal_start_code = b'\x00\x00\x00\x01'
        fragment_buffer = b''
        
        for pkt in rtp_packets:
            payload = pkt['payload']
            if len(payload) < 2:
                continue
            
            # Check for FU-A fragmentation (type 28)
            nal_type = payload[0] & 0x1F
            
            if nal_type == 28:  # FU-A
                fu_indicator = payload[0]
                fu_header = payload[1]
                
                start_bit = (fu_header >> 7) & 0x1
                end_bit = (fu_header >> 6) & 0x1
                nal_unit_type = fu_header & 0x1F
                
                if start_bit:
                    # Start of fragment
                    if fragment_buffer:
                        h264_data += nal_start_code + fragment_buffer
                    # Reconstruct NAL header
                    nal_header = (fu_indicator & 0xE0) | nal_unit_type
                    fragment_buffer = bytes([nal_header]) + payload[2:]
                else:
                    # Continuation or end
                    fragment_buffer += payload[2:]
                
                if end_bit:
                    # End of fragment
                    h264_data += nal_start_code + fragment_buffer
                    fragment_buffer = b''
            else:
                # Single NAL unit
                if fragment_buffer:
                    h264_data += nal_start_code + fragment_buffer
                    fragment_buffer = b''
                h264_data += nal_start_code + payload
        
        # Don't forget remaining fragment
        if fragment_buffer:
            h264_data += nal_start_code + fragment_buffer
        
        return h264_data
    
    def _try_convert_h264(self, input_file, method_name):
        """Try to convert H.264 file to MP4 with various options"""
        output_file = f'recovered_{method_name}.mp4'
        
        conversion_commands = [
            # Method 1: Direct copy
            ['ffmpeg', '-f', 'h264', '-i', input_file, '-c:v', 'copy', '-y', output_file],
            # Method 2: Re-encode
            ['ffmpeg', '-f', 'h264', '-i', input_file, '-c:v', 'libx264', '-y', output_file],
            # Method 3: With frame rate
            ['ffmpeg', '-f', 'h264', '-framerate', str(self.fps), '-i', input_file, '-c:v', 'copy', '-y', output_file],
            # Method 4: Analyze duration first
            ['ffmpeg', '-f', 'h264', '-analyzeduration', '100M', '-probesize', '100M', '-i', input_file, '-c:v', 'copy', '-y', output_file],
        ]
        
        for i, cmd in enumerate(conversion_commands, 1):
            try:
                print(f"[*] Conversion attempt {i}/{len(conversion_commands)}...", end=' ')
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    print("SUCCESS!")
                    print(f"[+] Video saved: {output_file}")
                    
                    # Verify with ffprobe
                    try:
                        probe_cmd = ['ffprobe', '-v', 'error', '-show_entries', 
                                   'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', 
                                   output_file]
                        duration = subprocess.run(probe_cmd, capture_output=True, text=True)
                        if duration.returncode == 0 and duration.stdout.strip():
                            print(f"[+] Duration: {float(duration.stdout.strip()):.2f} seconds")
                    except:
                        pass
                    
                    return True
                else:
                    print("failed")
            except subprocess.TimeoutExpired:
                print("timeout")
            except Exception as e:
                print(f"error: {e}")
        
        return False
    
    def extract_http_video(self):
        """Extract complete video file from HTTP stream"""
        print("[*] Extracting HTTP video stream...")
        
        stream_info = self.stream_info.get('http_video')
        video_data = b''
        in_body = False
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
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
        
        # Detect format
        if video_data.startswith(b'\x00\x00\x00'):
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
        
        try:
            print("[*] Converting with ffmpeg...")
            cmd = ['ffmpeg', '-i', output_file, '-c', 'copy', '-y', self.output_video]
            subprocess.run(cmd, capture_output=True, check=True)
            print(f"[+] Final video: {self.output_video}")
            return 1
        except:
            print(f"[!] Could not convert. Raw file: {output_file}")
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
            return False
    
    def extract(self):
        """Main extraction method"""
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
            self.extract_rtp_enhanced()
        
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
        print("\n[!] Extraction may have failed")
        print("[*] Check output files for partial results")


if __name__ == "__main__":
    main()
