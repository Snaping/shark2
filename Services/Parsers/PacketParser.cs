using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using NetworkPacketAnalyzer.Models;

namespace NetworkPacketAnalyzer.Services.Parsers;

public static class PacketParser
{
    public static PacketInfo Parse(byte[] rawData, DateTime timestamp)
    {
        var packet = new PacketInfo
        {
            Timestamp = timestamp,
            Length = rawData.Length,
            RawData = rawData,
            Protocol = ProtocolType.Unknown
        };

        try
        {
            ParseEthernet(packet, rawData);
            BuildDetailsTree(packet);
        }
        catch
        {
            packet.Info = "Malformed packet";
        }

        return packet;
    }

    private static void ParseEthernet(PacketInfo packet, byte[] data)
    {
        if (data.Length < 14) return;

        var ethHeader = new EthernetHeaderInfo
        {
            Destination = new PhysicalAddress(data.Take(6).ToArray()),
            Source = new PhysicalAddress(data.Skip(6).Take(6).ToArray()),
            Type = (ushort)((data[12] << 8) | data[13])
        };

        packet.EthernetHeader = ethHeader;
        packet.SourceMac = ethHeader.Source;
        packet.DestinationMac = ethHeader.Destination;
        packet.Protocol = ProtocolType.Ethernet;

        int payloadOffset = 14;

        switch (ethHeader.Type)
        {
            case 0x0800:
                ParseIPv4(packet, data, payloadOffset);
                break;
            case 0x86DD:
                packet.Protocol = ProtocolType.IPv6;
                packet.Info = "IPv6 Packet";
                break;
            case 0x0806:
                ParseArp(packet, data, payloadOffset);
                break;
            default:
                packet.Info = $"Ethernet Type: 0x{ethHeader.Type:X4}";
                break;
        }
    }

    private static void ParseIPv4(PacketInfo packet, byte[] data, int offset)
    {
        if (data.Length < offset + 20) return;

        int versionAndIhl = data[offset];
        int version = (versionAndIhl >> 4) & 0x0F;
        int ihl = versionAndIhl & 0x0F;
        int headerLength = ihl * 4;
        int totalLength = (data[offset + 2] << 8) | data[offset + 3];
        int ttl = data[offset + 8];
        int protocol = data[offset + 9];
        ushort checksum = (ushort)((data[offset + 10] << 8) | data[offset + 11]);
        ushort identification = (ushort)((data[offset + 4] << 8) | data[offset + 5]);
        byte flags = (byte)((data[offset + 6] >> 5) & 0x07);
        int fragmentOffset = ((data[offset + 6] & 0x1F) << 8) | data[offset + 7];

        var ipHeader = new IpHeaderInfo
        {
            Version = version,
            HeaderLength = headerLength,
            TotalLength = totalLength,
            Ttl = ttl,
            Protocol = protocol,
            Checksum = checksum,
            Identification = identification,
            Flags = flags,
            FragmentOffset = fragmentOffset,
            Source = new IPAddress(data.Skip(offset + 12).Take(4).ToArray()),
            Destination = new IPAddress(data.Skip(offset + 16).Take(4).ToArray())
        };

        packet.IpHeader = ipHeader;
        packet.SourceIp = ipHeader.Source;
        packet.DestinationIp = ipHeader.Destination;
        packet.Protocol = ProtocolType.IPv4;

        int payloadStart = offset + headerLength;

        switch (protocol)
        {
            case 6:
                ParseTcp(packet, data, payloadStart);
                break;
            case 17:
                ParseUdp(packet, data, payloadStart);
                break;
            case 1:
                packet.Protocol = ProtocolType.ICMP;
                packet.Info = $"ICMP, Length={totalLength}";
                break;
            default:
                packet.Info = $"IPv4 Protocol={protocol}, Length={totalLength}";
                break;
        }
    }

    private static void ParseTcp(PacketInfo packet, byte[] data, int offset)
    {
        if (data.Length < offset + 20) return;

        int sourcePort = (data[offset] << 8) | data[offset + 1];
        int destPort = (data[offset + 2] << 8) | data[offset + 3];
        uint seqNum = (uint)((data[offset + 4] << 24) | (data[offset + 5] << 16) |
                             (data[offset + 6] << 8) | data[offset + 7]);
        uint ackNum = (uint)((data[offset + 8] << 24) | (data[offset + 9] << 16) |
                             (data[offset + 10] << 8) | data[offset + 11]);
        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int headerLength = dataOffset * 4;
        var flags = (TcpFlags)data[offset + 13];
        ushort windowSize = (ushort)((data[offset + 14] << 8) | data[offset + 15]);
        ushort checksum = (ushort)((data[offset + 16] << 8) | data[offset + 17]);
        ushort urgentPtr = (ushort)((data[offset + 18] << 8) | data[offset + 19]);

        byte[]? options = null;
        if (headerLength > 20)
        {
            int optionsLength = headerLength - 20;
            options = data.Skip(offset + 20).Take(optionsLength).ToArray();
        }

        byte[]? payload = null;
        int payloadStart = offset + headerLength;
        if (data.Length > payloadStart)
        {
            payload = data.Skip(payloadStart).ToArray();
        }

        var tcpHeader = new TcpHeaderInfo
        {
            SourcePort = sourcePort,
            DestinationPort = destPort,
            SequenceNumber = seqNum,
            AcknowledgmentNumber = ackNum,
            HeaderLength = headerLength,
            Flags = flags,
            WindowSize = windowSize,
            Checksum = checksum,
            UrgentPointer = urgentPtr,
            Options = options,
            Payload = payload
        };

        packet.TcpHeader = tcpHeader;
        packet.SourcePort = sourcePort;
        packet.DestinationPort = destPort;
        packet.Protocol = ProtocolType.TCP;

        var flagsStr = new List<string>();
        if (flags.HasFlag(TcpFlags.SYN)) flagsStr.Add("SYN");
        if (flags.HasFlag(TcpFlags.ACK)) flagsStr.Add("ACK");
        if (flags.HasFlag(TcpFlags.FIN)) flagsStr.Add("FIN");
        if (flags.HasFlag(TcpFlags.RST)) flagsStr.Add("RST");
        if (flags.HasFlag(TcpFlags.PSH)) flagsStr.Add("PSH");
        if (flags.HasFlag(TcpFlags.URG)) flagsStr.Add("URG");

        packet.Info = $"{sourcePort} → {destPort} [{string.Join(",", flagsStr)}] Seq={seqNum}";

        if (payload != null && payload.Length > 0)
        {
            TryParseHttp(packet, payload, sourcePort, destPort);
        }
    }

    private static void ParseUdp(PacketInfo packet, byte[] data, int offset)
    {
        if (data.Length < offset + 8) return;

        int sourcePort = (data[offset] << 8) | data[offset + 1];
        int destPort = (data[offset + 2] << 8) | data[offset + 3];
        int length = (data[offset + 4] << 8) | data[offset + 5];
        ushort checksum = (ushort)((data[offset + 6] << 8) | data[offset + 7]);

        byte[]? payload = null;
        if (data.Length > offset + 8)
        {
            payload = data.Skip(offset + 8).ToArray();
        }

        var udpHeader = new UdpHeaderInfo
        {
            SourcePort = sourcePort,
            DestinationPort = destPort,
            Length = length,
            Checksum = checksum,
            Payload = payload
        };

        packet.UdpHeader = udpHeader;
        packet.SourcePort = sourcePort;
        packet.DestinationPort = destPort;
        packet.Protocol = ProtocolType.UDP;
        packet.Info = $"{sourcePort} → {destPort} Length={length}";

        if (sourcePort == 53 || destPort == 53)
        {
            packet.Protocol = ProtocolType.DNS;
            packet.Info = $"DNS {sourcePort} → {destPort}";
        }
    }

    private static void ParseArp(PacketInfo packet, byte[] data, int offset)
    {
        if (data.Length < offset + 28) return;

        ushort hardwareType = (ushort)((data[offset] << 8) | data[offset + 1]);
        ushort protocolType = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
        byte hwLength = data[offset + 4];
        byte protoLength = data[offset + 5];
        ushort operation = (ushort)((data[offset + 6] << 8) | data[offset + 7]);

        int senderMacStart = offset + 8;
        int senderIpStart = senderMacStart + hwLength;
        int targetMacStart = senderIpStart + protoLength;
        int targetIpStart = targetMacStart + hwLength;

        var arpHeader = new ArpHeaderInfo
        {
            HardwareType = hardwareType,
            ProtocolType = protocolType,
            HardwareLength = hwLength,
            ProtocolLength = protoLength,
            Operation = operation,
            SenderMac = new PhysicalAddress(data.Skip(senderMacStart).Take(hwLength).ToArray()),
            SenderIp = new IPAddress(data.Skip(senderIpStart).Take(protoLength).ToArray()),
            TargetMac = new PhysicalAddress(data.Skip(targetMacStart).Take(hwLength).ToArray()),
            TargetIp = new IPAddress(data.Skip(targetIpStart).Take(protoLength).ToArray())
        };

        packet.ArpHeader = arpHeader;
        packet.SourceIp = arpHeader.SenderIp;
        packet.DestinationIp = arpHeader.TargetIp;
        packet.SourceMac = arpHeader.SenderMac;
        packet.DestinationMac = arpHeader.TargetMac;
        packet.Protocol = ProtocolType.ARP;

        string opStr = operation == 1 ? "Request" : "Reply";
        packet.Info = $"ARP {opStr} {arpHeader.SenderIp} → {arpHeader.TargetIp}";
    }

    private static void TryParseHttp(PacketInfo packet, byte[] payload, int sourcePort, int destPort)
    {
        if (payload.Length < 10) return;

        try
        {
            var text = Encoding.ASCII.GetString(payload);
            bool isRequest = false;
            bool isResponse = false;
            int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);

            if (headerEnd == -1)
            {
                headerEnd = text.IndexOf("\n\n", StringComparison.Ordinal);
            }

            string firstLine = string.Empty;
            int firstLineEnd = text.IndexOf('\r');
            if (firstLineEnd == -1) firstLineEnd = text.IndexOf('\n');
            if (firstLineEnd > 0)
            {
                firstLine = text.Substring(0, firstLineEnd).Trim();
            }

            string[] httpMethods = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE" };
            foreach (var method in httpMethods)
            {
                if (firstLine.StartsWith(method + " ", StringComparison.Ordinal))
                {
                    isRequest = true;
                    break;
                }
            }

            if (!isRequest && firstLine.StartsWith("HTTP/", StringComparison.Ordinal))
            {
                isResponse = true;
            }

            if (!isRequest && !isResponse) return;

            var httpInfo = new HttpInfo
            {
                IsRequest = isRequest
            };

            if (isRequest)
            {
                var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    httpInfo.Method = parts[0];
                    httpInfo.Url = parts[1];
                }
                if (parts.Length >= 3)
                {
                    httpInfo.Version = parts[2];
                }
            }
            else
            {
                var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    httpInfo.Version = parts[0];
                    if (int.TryParse(parts[1], out int statusCode))
                    {
                        httpInfo.StatusCode = statusCode;
                    }
                }
                if (parts.Length >= 3)
                {
                    httpInfo.StatusDescription = string.Join(" ", parts.Skip(2));
                }
            }

            if (headerEnd > 0)
            {
                var headerSection = text.Substring(0, headerEnd);
                var lines = headerSection.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines.Skip(1))
                {
                    int colonIdx = line.IndexOf(':');
                    if (colonIdx > 0)
                    {
                        string key = line.Substring(0, colonIdx).Trim();
                        string value = line.Substring(colonIdx + 1).Trim();
                        httpInfo.Headers[key] = value;

                        if (key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                        {
                            httpInfo.Host = value;
                        }
                    }
                }

                if (headerEnd + 4 < payload.Length)
                {
                    int bodyStart = headerEnd + 4;
                    httpInfo.Body = payload.Skip(bodyStart).ToArray();
                }
            }

            packet.HttpInfo = httpInfo;
            packet.Protocol = ProtocolType.HTTP;

            if (isRequest)
            {
                packet.Info = $"HTTP {httpInfo.Method} {httpInfo.Host}{httpInfo.Url}";
            }
            else
            {
                packet.Info = $"HTTP {httpInfo.StatusCode} {httpInfo.StatusDescription}";
            }
        }
        catch
        {
        }
    }

    private static void BuildDetailsTree(PacketInfo packet)
    {
        var root = new ObservableCollection<PacketDetailNode>();

        if (packet.EthernetHeader != null)
        {
            var ethNode = new PacketDetailNode
            {
                Name = "Ethernet II",
                Value = $"Src: {packet.EthernetHeader.Source}, Dst: {packet.EthernetHeader.Destination}",
                Children =
                [
                    new() { Name = "Destination", Value = packet.EthernetHeader.Destination?.ToString() ?? "N/A" },
                    new() { Name = "Source", Value = packet.EthernetHeader.Source?.ToString() ?? "N/A" },
                    new() { Name = "Type", Value = packet.EthernetHeader.TypeDisplay }
                ]
            };
            root.Add(ethNode);
        }

        if (packet.IpHeader != null)
        {
            var ipNode = new PacketDetailNode
            {
                Name = "IPv4",
                Value = $"Src: {packet.IpHeader.Source}, Dst: {packet.IpHeader.Destination}",
                Children =
                [
                    new() { Name = "Version", Value = packet.IpHeader.Version.ToString() },
                    new() { Name = "Header Length", Value = $"{packet.IpHeader.HeaderLength} bytes" },
                    new() { Name = "Total Length", Value = packet.IpHeader.TotalLength.ToString() },
                    new() { Name = "Identification", Value = $"0x{packet.IpHeader.Identification:X4}" },
                    new() { Name = "TTL", Value = packet.IpHeader.Ttl.ToString() },
                    new() { Name = "Protocol", Value = packet.IpHeader.ProtocolDisplay },
                    new() { Name = "Checksum", Value = $"0x{packet.IpHeader.Checksum:X4}" },
                    new() { Name = "Source", Value = packet.IpHeader.Source?.ToString() ?? "N/A" },
                    new() { Name = "Destination", Value = packet.IpHeader.Destination?.ToString() ?? "N/A" }
                ]
            };
            root.Add(ipNode);
        }

        if (packet.TcpHeader != null)
        {
            var tcpNode = new PacketDetailNode
            {
                Name = "TCP",
                Value = $"Src Port: {packet.TcpHeader.SourcePort}, Dst Port: {packet.TcpHeader.DestinationPort}",
                Children =
                [
                    new() { Name = "Source Port", Value = packet.TcpHeader.SourcePort.ToString() },
                    new() { Name = "Destination Port", Value = packet.TcpHeader.DestinationPort.ToString() },
                    new() { Name = "Sequence Number", Value = packet.TcpHeader.SequenceNumber.ToString() },
                    new() { Name = "Acknowledgment Number", Value = packet.TcpHeader.AcknowledgmentNumber.ToString() },
                    new() { Name = "Header Length", Value = $"{packet.TcpHeader.HeaderLength} bytes" },
                    new() { Name = "Flags", Value = packet.TcpHeader.Flags.ToString() },
                    new() { Name = "Window Size", Value = packet.TcpHeader.WindowSize.ToString() },
                    new() { Name = "Checksum", Value = $"0x{packet.TcpHeader.Checksum:X4}" },
                    new() { Name = "Urgent Pointer", Value = packet.TcpHeader.UrgentPointer.ToString() }
                ]
            };
            root.Add(tcpNode);
        }

        if (packet.UdpHeader != null)
        {
            var udpNode = new PacketDetailNode
            {
                Name = "UDP",
                Value = $"Src Port: {packet.UdpHeader.SourcePort}, Dst Port: {packet.UdpHeader.DestinationPort}",
                Children =
                [
                    new() { Name = "Source Port", Value = packet.UdpHeader.SourcePort.ToString() },
                    new() { Name = "Destination Port", Value = packet.UdpHeader.DestinationPort.ToString() },
                    new() { Name = "Length", Value = packet.UdpHeader.Length.ToString() },
                    new() { Name = "Checksum", Value = $"0x{packet.UdpHeader.Checksum:X4}" }
                ]
            };
            root.Add(udpNode);
        }

        if (packet.ArpHeader != null)
        {
            var arpNode = new PacketDetailNode
            {
                Name = "ARP",
                Value = $"{packet.ArpHeader.OperationDisplay}: {packet.ArpHeader.SenderIp} → {packet.ArpHeader.TargetIp}",
                Children =
                [
                    new() { Name = "Hardware Type", Value = $"0x{packet.ArpHeader.HardwareType:X4}" },
                    new() { Name = "Protocol Type", Value = $"0x{packet.ArpHeader.ProtocolType:X4}" },
                    new() { Name = "Operation", Value = packet.ArpHeader.OperationDisplay },
                    new() { Name = "Sender MAC", Value = packet.ArpHeader.SenderMac?.ToString() ?? "N/A" },
                    new() { Name = "Sender IP", Value = packet.ArpHeader.SenderIp?.ToString() ?? "N/A" },
                    new() { Name = "Target MAC", Value = packet.ArpHeader.TargetMac?.ToString() ?? "N/A" },
                    new() { Name = "Target IP", Value = packet.ArpHeader.TargetIp?.ToString() ?? "N/A" }
                ]
            };
            root.Add(arpNode);
        }

        if (packet.HttpInfo != null)
        {
            var httpChildren = new List<PacketDetailNode>
            {
                new() { Name = "Type", Value = packet.HttpInfo.IsRequest ? "Request" : "Response" }
            };

            if (packet.HttpInfo.IsRequest)
            {
                httpChildren.Add(new() { Name = "Method", Value = packet.HttpInfo.Method });
                httpChildren.Add(new() { Name = "URL", Value = packet.HttpInfo.Url });
                httpChildren.Add(new() { Name = "Host", Value = packet.HttpInfo.Host });
                httpChildren.Add(new() { Name = "Full URL", Value = packet.HttpInfo.FullUrl });
            }
            else
            {
                httpChildren.Add(new() { Name = "Status Code", Value = packet.HttpInfo.StatusCode.ToString() });
                httpChildren.Add(new() { Name = "Status", Value = packet.HttpInfo.StatusDescription });
            }

            httpChildren.Add(new() { Name = "Version", Value = packet.HttpInfo.Version });

            var headerNodes = new List<PacketDetailNode>();
            foreach (var kvp in packet.HttpInfo.Headers)
            {
                headerNodes.Add(new PacketDetailNode { Name = kvp.Key, Value = kvp.Value });
            }
            httpChildren.Add(new PacketDetailNode
            {
                Name = "Headers",
                Value = $"{packet.HttpInfo.Headers.Count} items",
                Children = new ObservableCollection<PacketDetailNode>(headerNodes)
            });

            var httpNode = new PacketDetailNode
            {
                Name = "HTTP",
                Value = packet.HttpInfo.IsRequest
                    ? $"{packet.HttpInfo.Method} {packet.HttpInfo.Url}"
                    : $"{packet.HttpInfo.StatusCode} {packet.HttpInfo.StatusDescription}",
                Children = new ObservableCollection<PacketDetailNode>(httpChildren)
            };
            root.Add(httpNode);
        }

        packet.Details = root;
    }

    public static string HexDump(byte[]? data)
    {
        if (data == null || data.Length == 0) return string.Empty;

        var sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            int lineLength = Math.Min(bytesPerLine, data.Length - i);

            sb.Append($"{i:X4}  ");

            for (int j = 0; j < bytesPerLine; j++)
            {
                if (j < lineLength)
                {
                    sb.Append($"{data[i + j]:X2} ");
                }
                else
                {
                    sb.Append("   ");
                }
                if (j == 7) sb.Append(' ');
            }

            sb.Append(' ');

            for (int j = 0; j < lineLength; j++)
            {
                byte b = data[i + j];
                char c = b >= 32 && b < 127 ? (char)b : '.';
                sb.Append(c);
            }

            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }

    public static string[] GetHexLines(byte[]? data)
    {
        if (data == null || data.Length == 0) return [];

        var lines = new List<string>();
        int bytesPerLine = 16;

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            var sb = new StringBuilder();
            int lineLength = Math.Min(bytesPerLine, data.Length - i);

            sb.Append($"{i:X4}  ");

            for (int j = 0; j < bytesPerLine; j++)
            {
                if (j < lineLength)
                {
                    sb.Append($"{data[i + j]:X2} ");
                }
                else
                {
                    sb.Append("   ");
                }
                if (j == 7) sb.Append(' ');
            }

            sb.Append(' ');

            for (int j = 0; j < lineLength; j++)
            {
                byte b = data[i + j];
                char c = b >= 32 && b < 127 ? (char)b : '.';
                sb.Append(c);
            }

            lines.Add(sb.ToString());
        }

        return [.. lines];
    }
}
