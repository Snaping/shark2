using System.Collections.ObjectModel;
using NetworkPacketAnalyzer.Models;

namespace NetworkPacketAnalyzer.Services.Statistics;

public interface IPacketStatisticsService
{
    ObservableCollection<ProtocolStat> ProtocolStats { get; }
    ObservableCollection<RateDataPoint> PacketRateHistory { get; }

    int TotalPackets { get; }
    long TotalBytes { get; }
    double CurrentPacketsPerSecond { get; }

    event Action? StatisticsUpdated;

    void AddPacket(PacketInfo packet);
    void Reset();
    void StartRateSampling();
    void StopRateSampling();
}

public class ProtocolStat
{
    public ProtocolType Protocol { get; set; }
    public int Count { get; set; }
    public long Bytes { get; set; }
    public string ProtocolDisplay => Protocol.ToString().ToUpper();
    public double Percentage { get; set; }
}

public class RateDataPoint
{
    public DateTime Time { get; set; }
    public double PacketsPerSecond { get; set; }
    public double BytesPerSecond { get; set; }
    public string TimeDisplay => Time.ToString("HH:mm:ss");
}

public class PacketStatisticsService : IPacketStatisticsService
{
    private readonly Dictionary<ProtocolType, int> _protocolCounts = new();
    private readonly Dictionary<ProtocolType, long> _protocolBytes = new();
    private readonly object _lock = new();
    private int _totalPackets;
    private long _totalBytes;

    private int _currentSecondPackets;
    private long _currentSecondBytes;
    private DateTime _currentSecondStart;

    private System.Timers.Timer? _rateTimer;
    private bool _isSampling;

    public ObservableCollection<ProtocolStat> ProtocolStats { get; } = [];
    public ObservableCollection<RateDataPoint> PacketRateHistory { get; } = [];

    public int TotalPackets
    {
        get
        {
            lock (_lock) return _totalPackets;
        }
    }

    public long TotalBytes
    {
        get
        {
            lock (_lock) return _totalBytes;
        }
    }

    public double CurrentPacketsPerSecond { get; private set; }

    public event Action? StatisticsUpdated;

    public PacketStatisticsService()
    {
        _currentSecondStart = DateTime.Now;
    }

    public void AddPacket(PacketInfo packet)
    {
        lock (_lock)
        {
            _totalPackets++;
            _totalBytes += packet.Length;

            var proto = packet.Protocol;
            if (!_protocolCounts.ContainsKey(proto))
            {
                _protocolCounts[proto] = 0;
                _protocolBytes[proto] = 0;
            }
            _protocolCounts[proto]++;
            _protocolBytes[proto] += packet.Length;

            _currentSecondPackets++;
            _currentSecondBytes += packet.Length;
        }

        UpdateProtocolStats();
    }

    private void UpdateProtocolStats()
    {
        lock (_lock)
        {
            var stats = _protocolCounts.Select(kvp => new ProtocolStat
            {
                Protocol = kvp.Key,
                Count = kvp.Value,
                Bytes = _protocolBytes[kvp.Key],
                Percentage = _totalPackets > 0 ? (double)kvp.Value / _totalPackets * 100 : 0
            }).OrderByDescending(s => s.Count).ToList();

            System.Windows.Application.Current?.Dispatcher.Invoke(() =>
            {
                ProtocolStats.Clear();
                foreach (var stat in stats)
                {
                    ProtocolStats.Add(stat);
                }
            });
        }

        StatisticsUpdated?.Invoke();
    }

    public void Reset()
    {
        lock (_lock)
        {
            _totalPackets = 0;
            _totalBytes = 0;
            _protocolCounts.Clear();
            _protocolBytes.Clear();
            _currentSecondPackets = 0;
            _currentSecondBytes = 0;
            _currentSecondStart = DateTime.Now;
        }

        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            ProtocolStats.Clear();
            PacketRateHistory.Clear();
        });

        CurrentPacketsPerSecond = 0;
        StatisticsUpdated?.Invoke();
    }

    public void StartRateSampling()
    {
        if (_isSampling) return;

        _isSampling = true;
        _currentSecondStart = DateTime.Now;
        _currentSecondPackets = 0;
        _currentSecondBytes = 0;

        _rateTimer = new System.Timers.Timer(1000);
        _rateTimer.Elapsed += (s, e) => SampleRate();
        _rateTimer.Start();
    }

    public void StopRateSampling()
    {
        _isSampling = false;
        _rateTimer?.Stop();
        _rateTimer?.Dispose();
        _rateTimer = null;
    }

    private void SampleRate()
    {
        double pps, bps;
        lock (_lock)
        {
            pps = _currentSecondPackets;
            bps = _currentSecondBytes;
            _currentSecondPackets = 0;
            _currentSecondBytes = 0;
        }

        CurrentPacketsPerSecond = pps;

        var dataPoint = new RateDataPoint
        {
            Time = DateTime.Now,
            PacketsPerSecond = pps,
            BytesPerSecond = bps
        };

        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            PacketRateHistory.Add(dataPoint);

            if (PacketRateHistory.Count > 60)
            {
                PacketRateHistory.RemoveAt(0);
            }
        });

        StatisticsUpdated?.Invoke();
    }
}
