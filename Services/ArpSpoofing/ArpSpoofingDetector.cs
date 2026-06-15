using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using NetworkPacketAnalyzer.Models;

namespace NetworkPacketAnalyzer.Services.ArpSpoofing;

public interface IArpSpoofingDetector
{
    ObservableCollection<ArpSpoofAlert> Alerts { get; }
    bool DetectionEnabled { get; set; }

    event Action<ArpSpoofAlert>? AlertDetected;

    void AnalyzePacket(PacketInfo packet);
    void Reset();
}

public class ArpSpoofAlert
{
    public IPAddress? IpAddress { get; set; }
    public List<PhysicalAddress> MacAddresses { get; set; } = [];
    public DateTime FirstDetected { get; set; }
    public DateTime LastDetected { get; set; }
    public int Count { get; set; }
    public string Message { get; set; } = string.Empty;
    public string IpDisplay => IpAddress?.ToString() ?? "Unknown";
    public string MacsDisplay => string.Join(", ", MacAddresses);
}

public class ArpSpoofingDetector : IArpSpoofingDetector
{
    private readonly Dictionary<IPAddress, List<PhysicalAddress>> _ipToMacs = new();
    private readonly object _lock = new();

    public ObservableCollection<ArpSpoofAlert> Alerts { get; } = [];
    public bool DetectionEnabled { get; set; } = true;

    public event Action<ArpSpoofAlert>? AlertDetected;

    public void AnalyzePacket(PacketInfo packet)
    {
        if (!DetectionEnabled) return;
        if (packet.ArpHeader == null) return;

        lock (_lock)
        {
            ProcessArpEntry(packet.ArpHeader.SenderIp, packet.ArpHeader.SenderMac, packet.Timestamp);

            if (packet.ArpHeader.Operation == 2 && packet.ArpHeader.TargetMac != null)
            {
                ProcessArpEntry(packet.ArpHeader.TargetIp, packet.ArpHeader.TargetMac, packet.Timestamp);
            }
        }
    }

    private void ProcessArpEntry(IPAddress? ip, PhysicalAddress? mac, DateTime timestamp)
    {
        if (ip == null || mac == null) return;
        if (IPAddress.Any.Equals(ip) || IPAddress.Broadcast.Equals(ip)) return;

        if (!_ipToMacs.ContainsKey(ip))
        {
            _ipToMacs[ip] = [mac];
            return;
        }

        var macs = _ipToMacs[ip];

        if (!macs.Contains(mac))
        {
            macs.Add(mac);

            if (macs.Count >= 2)
            {
                var alert = new ArpSpoofAlert
                {
                    IpAddress = ip,
                    MacAddresses = new List<PhysicalAddress>(macs),
                    FirstDetected = timestamp,
                    LastDetected = timestamp,
                    Count = 1,
                    Message = $"ARP Spoofing detected: IP {ip} has {macs.Count} MAC addresses: {string.Join(", ", macs)}"
                };

                var existing = Alerts.FirstOrDefault(a => a.IpAddress?.Equals(ip) == true);
                if (existing != null)
                {
                    existing.MacAddresses = new List<PhysicalAddress>(macs);
                    existing.LastDetected = timestamp;
                    existing.Count++;
                    existing.Message = $"ARP Spoofing detected: IP {ip} has {macs.Count} MAC addresses: {string.Join(", ", macs)}";
                }
                else
                {
                    Alerts.Add(alert);
                }

                AlertDetected?.Invoke(alert);
            }
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _ipToMacs.Clear();
            Alerts.Clear();
        }
    }
}
