using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using NetworkPacketAnalyzer.Models;
using NetworkPacketAnalyzer.Services.Parsers;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetworkPacketAnalyzer.Services.Capture;

public interface IPacketCaptureService
{
    ObservableCollection<LibPcapLiveDevice> AvailableDevices { get; }
    bool IsCapturing { get; }
    LibPcapLiveDevice? SelectedDevice { get; set; }

    event Action<PacketInfo>? PacketReceived;
    event Action<string>? StatusChanged;

    void RefreshDevices();
    Task StartCaptureAsync(CancellationToken cancellationToken);
    void StopCapture();
}

public class PacketCaptureService : IPacketCaptureService
{
    private LibPcapLiveDevice? _selectedDevice;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private int _packetIndex = 0;

    public ObservableCollection<LibPcapLiveDevice> AvailableDevices { get; } = [];
    public bool IsCapturing { get; private set; }

    public LibPcapLiveDevice? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (IsCapturing) return;
            _selectedDevice = value;
        }
    }

    public event Action<PacketInfo>? PacketReceived;
    public event Action<string>? StatusChanged;

    public PacketCaptureService()
    {
        RefreshDevices();
    }

    public void RefreshDevices()
    {
        AvailableDevices.Clear();
        try
        {
            foreach (var dev in LibPcapLiveDeviceList.Instance)
            {
                AvailableDevices.Add(dev);
            }
            StatusChanged?.Invoke($"Found {AvailableDevices.Count} network interfaces");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Error enumerating devices: {ex.Message}");
        }
    }

    public Task StartCaptureAsync(CancellationToken cancellationToken)
    {
        if (IsCapturing) return Task.CompletedTask;
        if (_selectedDevice == null)
        {
            StatusChanged?.Invoke("Please select a network interface");
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _packetIndex = 0;
        IsCapturing = true;
        StatusChanged?.Invoke($"Starting capture on {_selectedDevice.Name}...");

        _captureTask = Task.Run(() => RunCapture(_selectedDevice, _cts.Token), _cts.Token);
        return _captureTask;
    }

    private void RunCapture(LibPcapLiveDevice device, CancellationToken token)
    {
        try
        {
            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();

            StatusChanged?.Invoke($"Capturing on {device.Name}...");

            while (!token.IsCancellationRequested)
            {
                Thread.Sleep(100);
            }
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Capture error: {ex.Message}");
        }
        finally
        {
            try
            {
                device.StopCapture();
                device.Close();
                device.OnPacketArrival -= OnPacketArrival;
            }
            catch { }

            IsCapturing = false;
            StatusChanged?.Invoke("Capture stopped");
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawData = e.Data.ToArray();
            var packet = PacketParser.Parse(rawData, e.Header.Timeval.Date);
            packet.Index = Interlocked.Increment(ref _packetIndex);
            PacketReceived?.Invoke(packet);
        }
        catch
        {
        }
    }

    public void StopCapture()
    {
        if (!IsCapturing) return;
        _cts?.Cancel();
        try
        {
            _captureTask?.Wait(2000);
        }
        catch { }
        _cts?.Dispose();
        _cts = null;
        _captureTask = null;
    }
}
