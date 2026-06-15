using System.Collections.ObjectModel;
using System.Net;
using System.Text;
using NetworkPacketAnalyzer.Models;

namespace NetworkPacketAnalyzer.Services.TcpStream;

public interface ITcpStreamReassembler
{
    ObservableCollection<TcpStreamInfo> Streams { get; }

    void AnalyzePacket(PacketInfo packet);
    void Reset();
    TcpStreamInfo? GetStream(string streamId);
}

public class TcpStreamInfo
{
    public string StreamId { get; set; } = string.Empty;
    public IPAddress? SourceIp { get; set; }
    public IPAddress? DestinationIp { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public List<PacketInfo> Packets { get; set; } = [];
    public byte[]? ClientToServerData { get; set; }
    public byte[]? ServerToClientData { get; set; }
    public List<HttpRequestInfo> HttpRequests { get; set; } = [];
    public List<HttpResponseInfo> HttpResponses { get; set; } = [];
    public string DisplayName => $"{SourceIp}:{SourcePort} ↔ {DestinationIp}:{DestinationPort}";
}

public class HttpRequestInfo
{
    public string Method { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = [];
    public string FullUrl => !string.IsNullOrEmpty(Host) ? $"http://{Host}{Url}" : Url;
    public override string ToString() => $"{Method} {FullUrl}";
}

public class HttpResponseInfo
{
    public int StatusCode { get; set; }
    public string StatusDescription { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = [];
    public override string ToString() => $"{StatusCode} {StatusDescription}";
}

public class TcpStreamReassembler : ITcpStreamReassembler
{
    private readonly Dictionary<string, TcpStreamInfo> _streams = new();
    private readonly object _lock = new();

    public ObservableCollection<TcpStreamInfo> Streams { get; } = [];

    public void AnalyzePacket(PacketInfo packet)
    {
        if (packet.TcpHeader == null || packet.IpHeader == null) return;

        lock (_lock)
        {
            string streamId = GetStreamId(
                packet.IpHeader.Source?.ToString() ?? "",
                packet.IpHeader.Destination?.ToString() ?? "",
                packet.SourcePort,
                packet.DestinationPort);

            if (!_streams.TryGetValue(streamId, out var stream))
            {
                stream = new TcpStreamInfo
                {
                    StreamId = streamId,
                    SourceIp = packet.IpHeader.Source,
                    DestinationIp = packet.IpHeader.Destination,
                    SourcePort = packet.SourcePort,
                    DestinationPort = packet.DestinationPort
                };
                _streams[streamId] = stream;
                Streams.Add(stream);
            }

            stream.PacketCount++;
            stream.TotalBytes += packet.Length;
            stream.Packets.Add(packet);

            if (packet.HttpInfo != null)
            {
                if (packet.HttpInfo.IsRequest)
                {
                    var req = new HttpRequestInfo
                    {
                        Method = packet.HttpInfo.Method,
                        Url = packet.HttpInfo.Url,
                        Host = packet.HttpInfo.Host,
                        Version = packet.HttpInfo.Version,
                        Headers = new Dictionary<string, string>(packet.HttpInfo.Headers)
                    };
                    stream.HttpRequests.Add(req);
                }
                else
                {
                    var resp = new HttpResponseInfo
                    {
                        StatusCode = packet.HttpInfo.StatusCode,
                        StatusDescription = packet.HttpInfo.StatusDescription,
                        Version = packet.HttpInfo.Version,
                        Headers = new Dictionary<string, string>(packet.HttpInfo.Headers)
                    };
                    stream.HttpResponses.Add(resp);
                }
            }
        }
    }

    public TcpStreamInfo? GetStream(string streamId)
    {
        lock (_lock)
        {
            return _streams.GetValueOrDefault(streamId);
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _streams.Clear();
            Streams.Clear();
        }
    }

    private static string GetStreamId(string srcIp, string dstIp, int srcPort, int dstPort)
    {
        var pair1 = $"{srcIp}:{srcPort}";
        var pair2 = $"{dstIp}:{dstPort}";
        return string.CompareOrdinal(pair1, pair2) < 0 ? $"{pair1}-{pair2}" : $"{pair2}-{pair1}";
    }
}
