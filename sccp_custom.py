from scapy.packet import Packet
from scapy.fields import ByteEnumField, ByteField, ShortField, StrField, FieldLenField, ConditionalField
from scapy.all import SCTP
from scapy.packet import bind_layers

class SCCP(Packet):
    """
    SCCP (Signaling Connection Control Part) Protocol
    """
    name = "SCCP"
    fields_desc = [
        ByteField("protocol_class", 0),  # Protocol class (e.g., 0x00 for class 0)
        ByteEnumField("message_type", 9, {  # Message type (UDT, CR, etc.)
            0: "CR",   # Connection Request
            1: "CC",   # Connection Confirm
            9: "UDT",  # Unit Data
            17: "XUDT" # Extended Unit Data
        }),
        FieldLenField("called_party_len", None, length_of="called_party"),  # Length of the called party address
        StrField("called_party", ""),  # Called party address
        FieldLenField("calling_party_len", None, length_of="calling_party"),  # Length of the calling party address
        StrField("calling_party", ""),  # Calling party address
        StrField("data", "")  # Payload data
    ]

class XUDT(SCCP):
    """
    XUDT (Extended Unit Data Service) - a subtype of SCCP
    """
    name = "XUDT"
    fields_desc = SCCP.fields_desc + [
        ByteField("segment_number", 0),  # Segment number for segmented payloads
        ByteField("sequence_number", 0),  # Sequence number for segmented payloads
        ConditionalField(StrField("additional_data", ""), lambda pkt: pkt.message_type == 17)  # Additional data for XUDT
    ]

# Bind SCCP to SCTP
bind_layers(SCTP, SCCP)
bind_layers(SCCP, XUDT, message_type=17)  # Bind XUDT when message_type is 17

# Test Functionality
if __name__ == "__main__":
    # Create a sample SCCP packet
    pkt = SCCP(
        protocol_class=0,
        message_type=9,
        called_party="555555",
        calling_party="666666",
        data="Hello, this is SCCP payload!"
    )
    print("SCCP Packet Summary:")
    print(pkt.show())

    # Create a sample XUDT packet
    xudt_pkt = XUDT(
        protocol_class=0,
        message_type=17,
        called_party="555555",
        calling_party="666666",
        data="This is an XUDT payload.",
        segment_number=1,
        sequence_number=42
    )
    print("XUDT Packet Summary:")
    print(xudt_pkt.show())
