using NetworkPacketAnalyzer.Models;
using NetworkPacketAnalyzer.Services.Parsers;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetworkPacketAnalyzer.Services.PcapFile;

public interface IPcapFileService
{
    Task<List<PacketInfo>> ReadFileAsync(string filePath, CancellationToken cancellationToken);
    Task SaveToFileAsync(string filePath, List<PacketInfo> packets, CancellationToken cancellationToken);
    event Action<string>? StatusChanged;
}

public class PcapFileService : IPcapFileService
{
    public event Action<string>? StatusChanged;

    public async Task<List<PacketInfo>> ReadFileAsync(string filePath, CancellationToken cancellationToken)
    {
        var packets = new List<PacketInfo>();
        await Task.Run(() =>
        {
            try
            {
                StatusChanged?.Invoke($"Reading pcap file: {filePath}...");

                using var device = new CaptureFileReaderDevice(filePath);
                device.Open();

                int index = 0;
                PacketCapture e;
                while (device.GetNextPacket(out e) == GetPacketStatus.PacketRead)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var rawData = e.Data.ToArray();
                    var packet = PacketParser.Parse(rawData, e.Header.Timeval.Date);
                    packet.Index = ++index;
                    packets.Add(packet);
                }

                device.Close();
                StatusChanged?.Invoke($"Loaded {packets.Count} packets from file");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Error reading pcap file: {ex.Message}");
            }
        }, cancellationToken);

        return packets;
    }

    public async Task SaveToFileAsync(string filePath, List<PacketInfo> packets, CancellationToken cancellationToken)
    {
        await Task.Run(() =>
        {
            try
            {
                StatusChanged?.Invoke($"Saving {packets.Count} packets to {filePath}...");

                using var writer = new CaptureFileWriterDevice(filePath);
                writer.Open();

                foreach (var packet in packets)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (packet.RawData != null)
                    {
                        var timeval = new PosixTimeval(packet.Timestamp);
                        var rawPacket = new RawCapture(LinkLayers.Ethernet, timeval, packet.RawData);
                        writer.Write(rawPacket);
                    }
                }

                writer.Close();
                StatusChanged?.Invoke($"Successfully saved {packets.Count} packets to {filePath}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Error saving pcap file: {ex.Message}");
            }
        }, cancellationToken);
    }
}
