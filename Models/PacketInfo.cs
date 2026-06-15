using System;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;

namespace NetworkPacketAnalyzer.Models;

public class PacketInfo
{
    public int Index { get; set; }
    public DateTime Timestamp { get; set; }
    public string TimeDisplay => Timestamp.ToString("HH:mm:ss.fff");

    public PhysicalAddress? SourceMac { get; set; }
    public PhysicalAddress? DestinationMac { get; set; }
    public string? SourceMacDisplay => SourceMac?.ToString() ?? "N/A";
    public string? DestinationMacDisplay => DestinationMac?.ToString() ?? "N/A";

    public IPAddress? SourceIp { get; set; }
    public IPAddress? DestinationIp { get; set; }
    public string? SourceIpDisplay => SourceIp?.ToString() ?? "N/A";
    public string? DestinationIpDisplay => DestinationIp?.ToString() ?? "N/A";

    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }

    public ProtocolType Protocol { get; set; }
    public string ProtocolDisplay => Protocol.ToString().ToUpper();

    public int Length { get; set; }
    public string LengthDisplay => $"{Length} bytes";

    public string Info { get; set; } = string.Empty;

    public byte[]? RawData { get; set; }

    public EthernetHeaderInfo? EthernetHeader { get; set; }
    public IpHeaderInfo? IpHeader { get; set; }
    public TcpHeaderInfo? TcpHeader { get; set; }
    public UdpHeaderInfo? UdpHeader { get; set; }
    public ArpHeaderInfo? ArpHeader { get; set; }
    public HttpInfo? HttpInfo { get; set; }

    public ObservableCollection<PacketDetailNode> Details { get; set; } = [];
}

public class PacketDetailNode
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public ObservableCollection<PacketDetailNode>? Children { get; set; }
}

public enum ProtocolType
{
    Unknown,
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    HTTP,
    HTTPS,
    DNS
}

public class EthernetHeaderInfo
{
    public PhysicalAddress? Source { get; set; }
    public PhysicalAddress? Destination { get; set; }
    public ushort Type { get; set; }
    public string TypeDisplay => Type switch
    {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        0x8100 => "VLAN",
        _ => $"0x{Type:X4}"
    };
}

public class IpHeaderInfo
{
    public int Version { get; set; }
    public int HeaderLength { get; set; }
    public int TotalLength { get; set; }
    public int Ttl { get; set; }
    public int Protocol { get; set; }
    public string ProtocolDisplay => Protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => Protocol.ToString()
    };
    public IPAddress? Source { get; set; }
    public IPAddress? Destination { get; set; }
    public ushort Checksum { get; set; }
    public ushort Identification { get; set; }
    public byte Flags { get; set; }
    public int FragmentOffset { get; set; }
}

public class TcpHeaderInfo
{
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public uint SequenceNumber { get; set; }
    public uint AcknowledgmentNumber { get; set; }
    public int HeaderLength { get; set; }
    public TcpFlags Flags { get; set; }
    public ushort WindowSize { get; set; }
    public ushort Checksum { get; set; }
    public ushort UrgentPointer { get; set; }
    public byte[]? Options { get; set; }
    public byte[]? Payload { get; set; }
    public int PayloadLength => Payload?.Length ?? 0;
}

[Flags]
public enum TcpFlags : byte
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
}

public class UdpHeaderInfo
{
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public int Length { get; set; }
    public ushort Checksum { get; set; }
    public byte[]? Payload { get; set; }
    public int PayloadLength => Payload?.Length ?? 0;
}

public class ArpHeaderInfo
{
    public ushort HardwareType { get; set; }
    public ushort ProtocolType { get; set; }
    public byte HardwareLength { get; set; }
    public byte ProtocolLength { get; set; }
    public ushort Operation { get; set; }
    public string OperationDisplay => Operation switch
    {
        1 => "Request",
        2 => "Reply",
        _ => Operation.ToString()
    };
    public PhysicalAddress? SenderMac { get; set; }
    public IPAddress? SenderIp { get; set; }
    public PhysicalAddress? TargetMac { get; set; }
    public IPAddress? TargetIp { get; set; }
}

public class HttpInfo
{
    public bool IsRequest { get; set; }
    public string Method { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public int StatusCode { get; set; }
    public string StatusDescription { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = [];
    public byte[]? Body { get; set; }
    public string FullUrl => !string.IsNullOrEmpty(Host) && !string.IsNullOrEmpty(Url) ? $"http://{Host}{Url}" : Url;
}
