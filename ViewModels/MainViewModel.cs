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
    private CancellationTokenSource? _filterCts;

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

    [ObservableProperty]
    private bool _isApplyingFilter;

    public ObservableCollection<LibPcapLiveDevice> AvailableDevices => _captureService.AvailableDevices;
    public ObservableCollection<ProtocolStat> ProtocolStats => _statisticsService.ProtocolStats;
    public ObservableCollection<RateDataPoint> PacketRateHistory => _statisticsService.PacketRateHistory;
    public ObservableCollection<TcpStreamInfo> Streams => _streamReassembler.Streams;
    public ObservableCollection<ArpSpoofAlert> ArpAlerts => _arpDetector.Alerts;

    [ObservableProperty]
    private ObservableCollection<ISeries> _protocolPieSeries = [];

    [ObservableProperty]
    private ObservableCollection<ISeries> _packetRateSeries = [];

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
        ApplyFilterCommand = new RelayCommand(ExecuteApplyFilter);
        ClearFilterCommand = new RelayCommand(ExecuteClearFilter);
        OpenFileCommand = new RelayCommand(async () => await OpenFileAsync());
        SaveFileCommand = new RelayCommand(async () => await SaveFileAsync(), CanSaveFile);
        RefreshDevicesCommand = new RelayCommand(RefreshDevices);
        ToggleStatisticsCommand = new RelayCommand(() => ShowStatisticsPanel = !ShowStatisticsPanel);
        ToggleStreamsCommand = new RelayCommand(() => ShowStreamsPanel = !ShowStreamsPanel);
        ToggleAlertsCommand = new RelayCommand(() => ShowAlertsPanel = !ShowAlertsPanel);

        _captureService.PacketReceived += OnPacketReceived;
        _captureService.StatusChanged += OnStatusChanged;
        _pcapFileService.StatusChanged += OnStatusChanged;
        _arpDetector.AlertDetected += OnArpAlertDetected;
        _statisticsService.StatisticsUpdated += OnStatisticsUpdated;

        InitializeCharts();
    }

    private readonly ObservableCollection<double> _rateValues = [];
    private readonly SKColor[] _chartColors =
    [
        SKColors.SteelBlue,
        SKColors.MediumSeaGreen,
        SKColors.Orange,
        SKColors.MediumPurple,
        SKColors.IndianRed,
        SKColors.DarkCyan,
        SKColors.HotPink,
        SKColors.Goldenrod,
        SKColors.Teal,
        SKColors.Tomato
    ];

    private void InitializeCharts()
    {
        XAxisRate =
        [
            new Axis
            {
                Labeler = value => value.ToString("F0"),
                LabelsRotation = 0,
                SeparatorsPaint = new SolidColorPaint(SKColors.LightGray, 1)
            }
        ];

        YAxisRate =
        [
            new Axis
            {
                Labeler = value => value.ToString("N0"),
                MinStep = 1,
                SeparatorsPaint = new SolidColorPaint(SKColors.LightGray, 1)
            }
        ];

        PacketRateSeries = new ObservableCollection<ISeries>
        {
            new LineSeries<double>
            {
                Name = "Packets/sec",
                Values = _rateValues,
                Fill = new SolidColorPaint(new SKColor(100, 149, 237, 50)),
                GeometrySize = 4,
                Stroke = new SolidColorPaint(SKColors.SteelBlue, 2)
            }
        };

        ProtocolPieSeries = new ObservableCollection<ISeries>();
        UpdatePieChart();
    }

    private void OnStatisticsUpdated()
    {
        try
        {
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
            {
                UpdatePieChart();
                UpdateRateChart();
            });
        }
        catch
        {
        }
    }

    private void UpdatePieChart()
    {
        try
        {
            ProtocolPieSeries.Clear();

            if (ProtocolStats.Count == 0)
            {
                return;
            }

            int colorIndex = 0;

            foreach (var stat in ProtocolStats)
            {
                if (stat.Count <= 0) continue;

                var color = _chartColors[colorIndex % _chartColors.Length];

                ProtocolPieSeries.Add(new PieSeries<double>
                {
                    Name = $"{stat.ProtocolDisplay} ({stat.Count})",
                    Values = new ObservableCollection<double> { stat.Count },
                    Fill = new SolidColorPaint(color),
                    DataLabelsPaint = new SolidColorPaint(SKColors.Black),
                    DataLabelsSize = 11
                });

                colorIndex++;
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Chart error: {ex.Message}";
        }
    }

    private void UpdateRateChart()
    {
        try
        {
            _rateValues.Clear();
            foreach (var point in PacketRateHistory)
            {
                _rateValues.Add(point.PacketsPerSecond);
            }

            if (YAxisRate.Length > 0)
            {
                var maxVal = _rateValues.Count > 0 ? Math.Max(_rateValues.Max(), 10) : 10;
                YAxisRate[0].MaxLimit = maxVal * 1.1;
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Rate chart error: {ex.Message}";
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

    private void ExecuteApplyFilter()
    {
        if (IsApplyingFilter) return;
        _ = ApplyFilterAsync(FilterExpression);
    }

    private void ExecuteClearFilter()
    {
        FilterExpression = string.Empty;
        if (IsApplyingFilter) return;
        _ = ApplyFilterAsync(string.Empty);
    }

    private async Task ApplyFilterAsync(string expression)
    {
        _filterCts?.Cancel();
        _filterCts = new CancellationTokenSource();
        var token = _filterCts.Token;

        IsApplyingFilter = true;
        StatusMessage = "Applying filter...";

        try
        {
            _filterService.FilterEnabled = !string.IsNullOrWhiteSpace(expression);
            _filterService.FilterExpression = expression;

            List<PacketInfo> snapshot;
            lock (_packetsLock)
            {
                snapshot = new List<PacketInfo>(_allPackets);
            }

            var matched = await Task.Run(() =>
            {
                var result = new List<PacketInfo>();
                foreach (var packet in snapshot)
                {
                    token.ThrowIfCancellationRequested();
                    if (_filterService.Matches(packet))
                    {
                        result.Add(packet);
                    }
                }
                return result;
            }, token);

            token.ThrowIfCancellationRequested();

            FilteredPackets.Clear();
            foreach (var packet in matched)
            {
                FilteredPackets.Add(packet);
            }
            FilteredCount = matched.Count;
            StatusMessage = $"Filter applied: {FilteredCount}/{TotalPackets} packets shown";
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            StatusMessage = $"Filter error: {ex.Message}";
        }
        finally
        {
            IsApplyingFilter = false;
        }
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
                StatusMessage = $"Loading {dialog.FileName}...";
                var packets = await _pcapFileService.ReadFileAsync(dialog.FileName, CancellationToken.None);

                foreach (var packet in packets)
                {
                    _allPackets.Add(packet);
                    _statisticsService.AddPacket(packet);
                    _streamReassembler.AnalyzePacket(packet);
                    _arpDetector.AnalyzePacket(packet);
                }

                TotalPackets = packets.Count;
                await ApplyFilterAsync(FilterExpression);
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
                StatusMessage = "Saving...";
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
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
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
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            StatusMessage = message;
        });
    }

    private void OnArpAlertDetected(ArpSpoofAlert alert)
    {
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            StatusMessage = $"ALERT: {alert.Message}";
        });
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
