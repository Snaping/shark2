using System.Collections.ObjectModel;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using NetworkPacketAnalyzer.Models;
using NetworkPacketAnalyzer.Services.ArpSpoofing;
using NetworkPacketAnalyzer.Services.Capture;
using NetworkPacketAnalyzer.Services.Filtering;
using NetworkPacketAnalyzer.Services.Parsers;
using NetworkPacketAnalyzer.Services.PcapFile;
using NetworkPacketAnalyzer.Services.Statistics;
using NetworkPacketAnalyzer.Services.TcpStream;
using Microsoft.Win32;
using SharpPcap.LibPcap;
using SkiaSharp;

namespace NetworkPacketAnalyzer.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketFilterService _filterService;
    private readonly IPcapFileService _pcapFileService;
    private readonly IPacketStatisticsService _statisticsService;
    private readonly ITcpStreamReassembler _streamReassembler;
    private readonly IArpSpoofingDetector _arpDetector;

    private readonly List<PacketInfo> _allPackets = [];
    private readonly object _packetsLock = new();

    [ObservableProperty]
    private ObservableCollection<PacketInfo> _filteredPackets = [];

    [ObservableProperty]
    private PacketInfo? _selectedPacket;

    [ObservableProperty]
    private string _statusMessage = "Ready";

    [ObservableProperty]
    private bool _isCapturing;

    [ObservableProperty]
    private LibPcapLiveDevice? _selectedDevice;

    [ObservableProperty]
    private string _filterExpression = string.Empty;

    [ObservableProperty]
    private int _totalPackets;

    [ObservableProperty]
    private int _filteredCount;

    [ObservableProperty]
    private string[]? _hexLines;

    [ObservableProperty]
    private bool _showStatisticsPanel;

    [ObservableProperty]
    private bool _showStreamsPanel;

    [ObservableProperty]
    private bool _showAlertsPanel;

    [ObservableProperty]
    private TcpStreamInfo? _selectedStream;

    public ObservableCollection<LibPcapLiveDevice> AvailableDevices => _captureService.AvailableDevices;
    public ObservableCollection<ProtocolStat> ProtocolStats => _statisticsService.ProtocolStats;
    public ObservableCollection<RateDataPoint> PacketRateHistory => _statisticsService.PacketRateHistory;
    public ObservableCollection<TcpStreamInfo> Streams => _streamReassembler.Streams;
    public ObservableCollection<ArpSpoofAlert> ArpAlerts => _arpDetector.Alerts;

    [ObservableProperty]
    private ISeries[] _protocolPieSeries = [];

    [ObservableProperty]
    private ISeries[] _packetRateSeries = [];

    [ObservableProperty]
    private Axis[] _xAxisRate = [];

    [ObservableProperty]
    private Axis[] _yAxisRate = [];

    public IRelayCommand StartCaptureCommand { get; }
    public IRelayCommand StopCaptureCommand { get; }
    public IRelayCommand ClearPacketsCommand { get; }
    public IRelayCommand ApplyFilterCommand { get; }
    public IRelayCommand ClearFilterCommand { get; }
    public IRelayCommand OpenFileCommand { get; }
    public IRelayCommand SaveFileCommand { get; }
    public IRelayCommand RefreshDevicesCommand { get; }
    public IRelayCommand ToggleStatisticsCommand { get; }
    public IRelayCommand ToggleStreamsCommand { get; }
    public IRelayCommand ToggleAlertsCommand { get; }

    public MainViewModel(
        IPacketCaptureService captureService,
        IPacketFilterService filterService,
        IPcapFileService pcapFileService,
        IPacketStatisticsService statisticsService,
        ITcpStreamReassembler streamReassembler,
        IArpSpoofingDetector arpDetector)
    {
        _captureService = captureService;
        _filterService = filterService;
        _pcapFileService = pcapFileService;
        _statisticsService = statisticsService;
        _streamReassembler = streamReassembler;
        _arpDetector = arpDetector;

        StartCaptureCommand = new RelayCommand(StartCapture, CanStartCapture);
        StopCaptureCommand = new RelayCommand(StopCapture, CanStopCapture);
        ClearPacketsCommand = new RelayCommand(ClearPackets);
        ApplyFilterCommand = new RelayCommand(ApplyFilter);
        ClearFilterCommand = new RelayCommand(ClearFilter);
        OpenFileCommand = new RelayCommand(async () => await OpenFileAsync());
        SaveFileCommand = new RelayCommand(async () => await SaveFileAsync(), CanSaveFile);
        RefreshDevicesCommand = new RelayCommand(RefreshDevices);
        ToggleStatisticsCommand = new RelayCommand(() => ShowStatisticsPanel = !ShowStatisticsPanel);
        ToggleStreamsCommand = new RelayCommand(() => ShowStreamsPanel = !ShowStreamsPanel);
        ToggleAlertsCommand = new RelayCommand(() => ShowAlertsPanel = !ShowAlertsPanel);

        _captureService.PacketReceived += OnPacketReceived;
        _captureService.StatusChanged += OnStatusChanged;
        _filterService.FilterChanged += OnFilterChanged;
        _pcapFileService.StatusChanged += OnStatusChanged;
        _arpDetector.AlertDetected += OnArpAlertDetected;
        _statisticsService.StatisticsUpdated += OnStatisticsUpdated;

        InitializeCharts();
    }

    private void InitializeCharts()
    {
        _xAxisRate =
        [
            new Axis
            {
                Labeler = value => TimeSpan.FromSeconds(value).ToString(@"mm\:ss"),
                LabelsRotation = 0
            }
        ];

        _yAxisRate =
        [
            new Axis
            {
                Labeler = value => value.ToString("N0"),
                MinStep = 1
            }
        ];

        _packetRateSeries =
        [
            new LineSeries<double>
            {
                Name = "Packets/sec",
                Values = new ObservableCollection<double>(),
                Fill = null,
                GeometrySize = 5
            }
        ];

        UpdatePieChart();
    }

    private void OnStatisticsUpdated()
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            UpdatePieChart();
            UpdateRateChart();
        });
    }

    private void UpdatePieChart()
    {
        var colors = new[]
        {
            SKColors.Blue,
            SKColors.Green,
            SKColors.Orange,
            SKColors.Purple,
            SKColors.Red,
            SKColors.Teal,
            SKColors.Magenta,
            SKColors.DarkCyan,
            SKColors.Goldenrod,
            SKColors.IndianRed
        };

        var series = new List<ISeries>();
        int colorIndex = 0;

        foreach (var stat in ProtocolStats)
        {
            series.Add(new PieSeries<int>
            {
                Name = stat.ProtocolDisplay,
                Values = new ObservableCollection<int> { stat.Count },
                Fill = new SolidColorPaint(colors[colorIndex % colors.Length]),
                DataLabelsPaint = new SolidColorPaint(SKColors.White),
                DataLabelsSize = 12
            });
            colorIndex++;
        }

        ProtocolPieSeries = series.ToArray();
    }

    private void UpdateRateChart()
    {
        if (PacketRateHistory.Count == 0) return;

        var values = PacketRateHistory.Select(p => p.PacketsPerSecond).ToList();

        if (PacketRateSeries.Length > 0 && PacketRateSeries[0] is LineSeries<double> lineSeries)
        {
            var observableValues = (ObservableCollection<double>)lineSeries.Values!;
            observableValues.Clear();
            foreach (var v in values)
            {
                observableValues.Add(v);
            }
        }
    }

    private bool CanStartCapture() => !IsCapturing && SelectedDevice != null;
    private bool CanStopCapture() => IsCapturing;
    private bool CanSaveFile() => TotalPackets > 0;

    private void StartCapture()
    {
        if (SelectedDevice == null) return;

        _captureService.SelectedDevice = SelectedDevice;
        _ = _captureService.StartCaptureAsync(CancellationToken.None);
        _statisticsService.StartRateSampling();
        IsCapturing = true;

        StartCaptureCommand.NotifyCanExecuteChanged();
        StopCaptureCommand.NotifyCanExecuteChanged();
    }

    private void StopCapture()
    {
        _captureService.StopCapture();
        _statisticsService.StopRateSampling();
        IsCapturing = false;

        StartCaptureCommand.NotifyCanExecuteChanged();
        StopCaptureCommand.NotifyCanExecuteChanged();
    }

    private void ClearPackets()
    {
        lock (_packetsLock)
        {
            _allPackets.Clear();
        }
        FilteredPackets.Clear();
        _statisticsService.Reset();
        _streamReassembler.Reset();
        _arpDetector.Reset();
        TotalPackets = 0;
        FilteredCount = 0;
        SelectedPacket = null;
        HexLines = null;
        StatusMessage = "Packets cleared";
        SaveFileCommand.NotifyCanExecuteChanged();
    }

    private void ApplyFilter()
    {
        _filterService.FilterExpression = FilterExpression;
        _filterService.FilterEnabled = !string.IsNullOrWhiteSpace(FilterExpression);
        UpdateFilteredPackets();
    }

    private void ClearFilter()
    {
        FilterExpression = string.Empty;
        _filterService.FilterExpression = string.Empty;
        _filterService.FilterEnabled = false;
        UpdateFilteredPackets();
    }

    private async Task OpenFileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "PCAP files (*.pcap, *.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*",
            Title = "Open PCAP File"
        };

        if (dialog.ShowDialog() == true)
        {
            StopCapture();
            ClearPackets();

            try
            {
                var packets = await _pcapFileService.ReadFileAsync(dialog.FileName, CancellationToken.None);

                foreach (var packet in packets)
                {
                    _allPackets.Add(packet);
                    _statisticsService.AddPacket(packet);
                    _streamReassembler.AnalyzePacket(packet);
                    _arpDetector.AnalyzePacket(packet);
                }

                TotalPackets = packets.Count;
                UpdateFilteredPackets();
                StatusMessage = $"Loaded {packets.Count} packets from {dialog.FileName}";
                SaveFileCommand.NotifyCanExecuteChanged();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
            }
        }
    }

    private async Task SaveFileAsync()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "PCAP files (*.pcap)|*.pcap|All files (*.*)|*.*",
            Title = "Save PCAP File",
            FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                List<PacketInfo> packets;
                lock (_packetsLock)
                {
                    packets = new List<PacketInfo>(_allPackets);
                }
                await _pcapFileService.SaveToFileAsync(dialog.FileName, packets, CancellationToken.None);
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
            }
        }
    }

    private void RefreshDevices()
    {
        _captureService.RefreshDevices();
    }

    private void OnPacketReceived(PacketInfo packet)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            lock (_packetsLock)
            {
                _allPackets.Add(packet);
            }

            _statisticsService.AddPacket(packet);
            _streamReassembler.AnalyzePacket(packet);
            _arpDetector.AnalyzePacket(packet);

            TotalPackets++;

            if (_filterService.Matches(packet))
            {
                FilteredPackets.Add(packet);
                FilteredCount = FilteredPackets.Count;
            }

            SaveFileCommand.NotifyCanExecuteChanged();
        });
    }

    private void OnStatusChanged(string message)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            StatusMessage = message;
        });
    }

    private void OnFilterChanged()
    {
        UpdateFilteredPackets();
    }

    private void OnArpAlertDetected(ArpSpoofAlert alert)
    {
        StatusMessage = $"ALERT: {alert.Message}";
    }

    private void UpdateFilteredPackets()
    {
        FilteredPackets.Clear();
        int count = 0;

        lock (_packetsLock)
        {
            foreach (var packet in _allPackets)
            {
                if (_filterService.Matches(packet))
                {
                    FilteredPackets.Add(packet);
                    count++;
                }
            }
        }

        FilteredCount = count;
    }

    partial void OnSelectedPacketChanged(PacketInfo? value)
    {
        if (value?.RawData != null)
        {
            HexLines = PacketParser.GetHexLines(value.RawData);
        }
        else
        {
            HexLines = null;
        }
    }

    partial void OnSelectedDeviceChanged(LibPcapLiveDevice? value)
    {
        _captureService.SelectedDevice = value;
        StartCaptureCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsCapturingChanged(bool value)
    {
        StartCaptureCommand.NotifyCanExecuteChanged();
        StopCaptureCommand.NotifyCanExecuteChanged();
    }
}
