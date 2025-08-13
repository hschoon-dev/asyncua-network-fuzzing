import pyshark
import sys
import argparse
from pathlib import Path
#import re

sys.path.insert(0, "..")
script_base = Path(__file__).parent

# Parse command line arguments
parser = argparse.ArgumentParser(description='Convert pcapng captures to text files with OPC UA messages')
parser.add_argument('capture_file', nargs='?', help='Path to the pcapng capture file')
parser.add_argument('output_file', nargs='?', help='Path to the output text file')
args = parser.parse_args()

# Check if required arguments are provided
if not args.capture_file or not args.output_file:
    parser.print_usage()
    print("\nError: Both capture_file and output_file arguments are required")
    print("Convert pcapng captures to text files with OPC UA messages")
    print("\npositional arguments:")
    print("         capture_file  Path to the pcapng capture file")
    print("         output_file   Path to the output text file\n")
    print("Example: python pyshark-convert-captures.py capture.pcapng output.txt")
    sys.exit(1)

# Use provided file paths
# If the capture file path is not absolute, assume it's relative to the script directory
if not Path(args.capture_file).is_absolute():
    capture_file = script_base / args.capture_file
else:
    capture_file = Path(args.capture_file)

# For output file, also handle relative paths
if not Path(args.output_file).is_absolute():
    output_file = script_base / args.output_file
else:
    output_file = Path(args.output_file)

# Check if capture file exists
if not capture_file.exists():
    print(f"Error: Capture file '{capture_file}' does not exist")
    sys.exit(1)

# First, check if any OPC UA packets exist
capture = pyshark.FileCapture(str(capture_file), display_filter='opcua')
packet_count = 0

# Save the first readable text segment and raw bytes to a file
def save_readable_text_with_raw_bytes(binary_data, filename):
    """Save the first readable text segment with the raw bytes to a text file."""
    readable_text, _ = extract_readable_text(binary_data)
    
    # Format the string as requested: 'readable_text' : b'raw_bytes'
    if readable_text:
        first_readable = readable_text[0]
        raw_bytes_str = str(binary_data)
        
        # Create the formatted entry
        entry = f"'{first_readable}' : {raw_bytes_str}\n"
        
        # Write to file (append mode)
        with open(filename, 'a') as f:
            f.write(entry)
        
        print(f"Saved entry to {filename}:")
        print(entry)
        return True
    else:
        print("No readable text found in the binary data.")
        return False

# Save the demonstration data

def extract_readable_text(binary_data):
    """Extract all readable ASCII text from binary data."""
    result = []
    current_text = ""
    positions = []  # Track start and end positions
    start_pos = None
    
    for i, byte in enumerate(binary_data):
        # Check if byte is printable ASCII
        if 32 <= byte <= 126:
            if current_text == "":  # Start of a new text segment
                start_pos = i
            current_text += chr(byte)
        else:
            if current_text and len(current_text) >= 3:  # Only keep text segments of 3+ chars
                result.append(current_text)
                positions.append((start_pos, i - 1))  # End position is the last character
            current_text = ""
            start_pos = None
    
    # Add the last segment if it exists
    if current_text and len(current_text) >= 3:
        result.append(current_text)
        positions.append((start_pos, len(binary_data) - 1))
        
    return result, positions


def create_readable_enhanced_hex_string(binary_data):
    """Create a hex string with readable text parts embedded."""
    readable_parts, positions = extract_readable_text(binary_data)
    
    # Start with the standard hex string
    hex_string = ''.join('\\x{:02x}'.format(b) for b in binary_data)
    
    # Replace hex values with readable text for each position
    enhanced_string = hex_string
    offset = 0  # Track offset changes as we modify the string
    
    for text, (start, end) in zip(readable_parts, positions):
        # Calculate positions in the hex string
        hex_start = start * 4 + offset  # Each byte is represented as \xXX (4 chars)
        hex_end = (end + 1) * 4 + offset
        
        # Replace with the actual text without quotes
        replacement = text
        enhanced_string = enhanced_string[:hex_start] + replacement + enhanced_string[hex_end:]
        
        # Update offset for next replacements
        offset += len(replacement) - (hex_end - hex_start)
    
    return f"b'{enhanced_string}'"

def extract_readable_from_hex_string(hex_string):
    r"""Extract readable text from a hex string in \xXX format."""
    # Convert the hex string back to bytes
    # First, remove the b' prefix and ' suffix if present
    if hex_string.startswith("b'") and hex_string.endswith("'"):
        hex_string = hex_string[2:-1]
    
    # Replace \x escape sequences with actual bytes
    binary_data = b''
    i = 0
    while i < len(hex_string):
        if i+1 < len(hex_string) and hex_string[i:i+2] == '\\x':
            # Get the hex value after \x
            if i+3 < len(hex_string):
                hex_val = hex_string[i+2:i+4]
                try:
                    byte_val = int(hex_val, 16)
                    binary_data += bytes([byte_val])
                except ValueError:
                    # If not a valid hex, just skip
                    pass
                i += 4
            else:
                i += 2
        else:
            # For characters not in \x format, just add them directly
            binary_data += bytes([ord(hex_string[i])])
            i += 1
    
    return extract_readable_text(binary_data)[0]

print(f"Analyzing capture file: {capture_file}")
print(f"Output will be saved to: {output_file}")

# Let's look at packet types
for i, packet in enumerate(capture):
    packet_count += 1
    print(f"\nPacket #{i+1}:")
    print(f"  Layers: {packet.layers}")
    
    if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
        raw_data = bytes.fromhex(packet.data.data.replace(':', ''))
        save_readable_text_with_raw_bytes(raw_data, str(output_file))
    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
        raw_data = bytes.fromhex(packet.tcp.payload.replace(':', ''))
        save_readable_text_with_raw_bytes(raw_data, str(output_file))

    # Try to find OPC UA data in different layers
    if hasattr(packet, 'opcua'):
        print(f"  OPC UA layer found!")
        print(f"  OPC UA message type: {packet.opcua.get_field_value('message_type') if hasattr(packet.opcua, 'message_type') else 'unknown'}")
        
        # Try different approaches to get the binary data
        if hasattr(packet, 'data'):
            if hasattr(packet.data, 'data'):
                print("  Data found in packet.data.data")
                raw_data = bytes.fromhex(packet.data.data.replace(':', ''))
                print(f"  Raw bytes: {raw_data}")
                
                # Create enhanced readable version
                #raw_bytes_readable_text_string = create_readable_enhanced_hex_string(raw_data)
                #print(f"  Raw bytes with readable text: {raw_bytes_readable_text_string}")
                
                # Extract readable text directly from raw_data
                #readable_text, _ = extract_readable_text(raw_data)
                #if readable_text:
                #    print(f"  Readable text segments: {readable_text}")

        elif hasattr(packet, 'tcp'):
            if hasattr(packet.tcp, 'payload'):
                print("  Data found in packet.tcp.payload")
                raw_data = bytes.fromhex(packet.tcp.payload.replace(':', ''))
                print(f"  Raw bytes: {raw_data}")
                
                # Create enhanced readable version
                #raw_bytes_readable_text_string = create_readable_enhanced_hex_string(raw_data)
                #print(f"  Raw bytes with readable text: {raw_bytes_readable_text_string}")
                
                # Extract readable text
                #readable_text, _ = extract_readable_text(raw_data)
                #if readable_text:
                #    print(f"  Readable text segments: {readable_text}")
    else:
        print("  No OPC UA layer found in this packet")

# Check if we processed any packets
if packet_count == 0:
    print("\nNo packets found. Possible issues:")
    print("1. The capture file might be empty or corrupt")
    print("2. The 'opcua' display filter might not match any packets")
    print("\nTry using a more general filter like 'tcp.port==4840' (standard OPC UA port)")

# Demonstration with a known OPC UA message
#print("\n\nDemonstration with known OPC UA message:")
#test_data = b'OPNF\x84\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00http://opcfoundation.org/UA/SecurityPolicy#None\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\xbe\x01\x00\x00\xb0V\xaf\x8a9\xd9\xd7\x01\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x80\xee6\x00'
#raw_bytes_readable_text_string = create_readable_enhanced_hex_string(test_data)
#print(f"Raw bytes with readable text embedded:")
#print(raw_bytes_readable_text_string)

#readable_text, _ = extract_readable_text(test_data)
#print(f"Extracted readable text segments: {readable_text}")