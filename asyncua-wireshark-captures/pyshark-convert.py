import pyshark
import sys
from pathlib import Path

sys.path.insert(0, "..")
script_base = Path(__file__).parent
capture_file = Path(script_base / "asyncua_captures.pcapng")

# First, check if any OPC UA packets exist
capture = pyshark.FileCapture(str(capture_file), display_filter='opcua')
packet_count = 0

def extract_readable_text(binary_data):
    """Extract all readable ASCII text from binary data."""
    result = []
    current_text = ""
    
    for byte in binary_data:
        # Check if byte is printable ASCII
        if 32 <= byte <= 126:
            current_text += chr(byte)
        else:
            if current_text and len(current_text) >= 3:  # Only keep text segments of 3+ chars
                result.append(current_text)
            current_text = ""
    
    # Add the last segment if it exists
    if current_text and len(current_text) >= 3:
        result.append(current_text)
        
    return result

print(f"Analyzing capture file: {capture_file}")

# Let's look at packet types
for i, packet in enumerate(capture):
    packet_count += 1
    print(f"\nPacket #{i+1}:")
    print(f"  Layers: {packet.layers}")
    
    # Try to find OPC UA data in different layers
    if hasattr(packet, 'opcua'):
        print(f"  OPC UA layer found!")
        print(f"  OPC UA message type: {packet.opcua.get_field_value('message_type') if hasattr(packet.opcua, 'message_type') else 'unknown'}")
        
        # Try different approaches to get the binary data
        if hasattr(packet, 'data'):
            if hasattr(packet.data, 'data'):
                print("  Data found in packet.data.data")
                raw_data = bytes.fromhex(packet.data.data.replace(':', ''))
                hex_string = ''.join('\\x{:02x}'.format(b) for b in raw_data)
                print(f"  Raw bytes: b'{hex_string}'")
                readable_text = extract_readable_text(raw_data)
                if readable_text:
                    print(f"  Readable text: {readable_text}")

        elif hasattr(packet, 'tcp'):
            if hasattr(packet.tcp, 'payload'):
                print("  Data found in packet.tcp.payload")
                raw_data = bytes.fromhex(packet.tcp.payload.replace(':', ''))
                hex_string = ''.join('\\x{:02x}'.format(b) for b in raw_data)
                print(f"  Raw bytes: b'{hex_string}'")
    else:
        print("  No OPC UA layer found in this packet")

# Check if we processed any packets
if packet_count == 0:
    print("\nNo packets found. Possible issues:")
    print("1. The capture file might be empty or corrupt")
    print("2. The 'opcua' display filter might not match any packets")
    print("\nTry using a more general filter like 'tcp.port==4840' (standard OPC UA port)")