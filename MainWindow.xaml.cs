using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using NetworkPacketAnalyzer.Models;
using NetworkPacketAnalyzer.Services.ArpSpoofing;
using NetworkPacketAnalyzer.Services.Capture;
using NetworkPacketAnalyzer.Services.Filtering;
using NetworkPacketAnalyzer.Services.PcapFile;
using NetworkPacketAnalyzer.Services.Statistics;
using NetworkPacketAnalyzer.Services.TcpStream;
using NetworkPacketAnalyzer.ViewModels;

namespace NetworkPacketAnalyzer;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        var captureService = new PacketCaptureService();
        var filterService = new PacketFilterService();
        var pcapFileService = new PcapFileService();
        var statisticsService = new PacketStatisticsService();
        var streamReassembler = new TcpStreamReassembler();
        var arpDetector = new ArpSpoofingDetector();

        DataContext = new MainViewModel(
            captureService,
            filterService,
            pcapFileService,
            statisticsService,
            streamReassembler,
            arpDetector);
    }

    private void FilterTextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.ApplyFilterCommand.Execute(null);
            }
        }
    }
}

public class ProtocolToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ProtocolType protocol)
        {
            return protocol switch
            {
                ProtocolType.TCP => Colors.Blue,
                ProtocolType.UDP => Colors.Green,
                ProtocolType.HTTP => Colors.Purple,
                ProtocolType.HTTPS => Colors.DarkMagenta,
                ProtocolType.ICMP => Colors.Orange,
                ProtocolType.ARP => Colors.DarkCyan,
                ProtocolType.DNS => Colors.DarkGreen,
                ProtocolType.IPv4 => Colors.Black,
                _ => Colors.Gray
            };
        }
        return Colors.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class ProtocolToBrushConverter : IValueConverter
{
    private readonly ProtocolToColorConverter _colorConverter = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var color = _colorConverter.Convert(value, targetType, parameter, culture);
        return new SolidColorBrush((Color)color);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Visibility visibility)
        {
            return visibility == Visibility.Visible;
        }
        return false;
    }
}
