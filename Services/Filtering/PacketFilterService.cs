using System.Net;
using NetworkPacketAnalyzer.Models;

namespace NetworkPacketAnalyzer.Services.Filtering;

public interface IPacketFilterService
{
    string FilterExpression { get; set; }
    bool FilterEnabled { get; set; }
    event Action? FilterChanged;

    bool Matches(PacketInfo packet);
    void UpdateFilter(string expression);
}

public class PacketFilterService : IPacketFilterService
{
    private string _filterExpression = string.Empty;
    private bool _filterEnabled = true;
    private Func<PacketInfo, bool>? _compiledFilter;

    public string FilterExpression
    {
        get => _filterExpression;
        set
        {
            _filterExpression = value;
            _compiledFilter = CompileFilter(value);
            FilterChanged?.Invoke();
        }
    }

    public bool FilterEnabled
    {
        get => _filterEnabled;
        set
        {
            _filterEnabled = value;
            FilterChanged?.Invoke();
        }
    }

    public event Action? FilterChanged;

    public bool Matches(PacketInfo packet)
    {
        if (!FilterEnabled || string.IsNullOrWhiteSpace(FilterExpression))
            return true;

        return _compiledFilter?.Invoke(packet) ?? true;
    }

    public void UpdateFilter(string expression)
    {
        FilterExpression = expression;
    }

    private static Func<PacketInfo, bool>? CompileFilter(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return _ => true;

        var tokens = expression.Split(new[] { "&&", "||" }, StringSplitOptions.None);
        var operators = new List<string>();
        int pos = 0;

        foreach (var token in tokens)
        {
            pos += token.Length;
            if (pos < expression.Length)
            {
                if (expression.Substring(pos, 2) == "&&")
                    operators.Add("&&");
                else if (expression.Substring(pos, 2) == "||")
                    operators.Add("||");
                pos += 2;
            }
        }

        var conditions = tokens.Select(t => ParseCondition(t.Trim())).Where(c => c != null).Select(c => c!).ToList();

        if (conditions.Count == 0)
            return _ => true;

        return packet =>
        {
            bool result = conditions[0](packet);
            for (int i = 0; i < operators.Count; i++)
            {
                if (i + 1 < conditions.Count)
                {
                    if (operators[i] == "&&")
                        result = result && conditions[i + 1](packet);
                    else
                        result = result || conditions[i + 1](packet);
                }
            }
            return result;
        };
    }

    private static Func<PacketInfo, bool>? ParseCondition(string condition)
    {
        condition = condition.Trim();
        if (string.IsNullOrEmpty(condition)) return null;

        string[] comparisonOps = { "==", "!=", ">=", "<=", ">", "<", "contains" };

        foreach (var op in comparisonOps)
        {
            int idx = condition.IndexOf(op, StringComparison.Ordinal);
            if (idx > 0)
            {
                string field = condition.Substring(0, idx).Trim();
                string value = condition.Substring(idx + op.Length).Trim();
                return CreateFilter(field, op, value);
            }
        }

        return null;
    }

    private static Func<PacketInfo, bool> CreateFilter(string field, string op, string value)
    {
        value = value.Trim('\'', '"');

        return field.ToLower() switch
        {
            "ip.src" or "src.ip" or "sourceip" => p => CompareIp(p.SourceIp, value, op),
            "ip.dst" or "dst.ip" or "destinationip" => p => CompareIp(p.DestinationIp, value, op),
            "ip.addr" or "ip" => p => CompareIp(p.SourceIp, value, op) || CompareIp(p.DestinationIp, value, op),

            "tcp.srcport" or "srcport" => p => ComparePort(p.SourcePort, value, op, p.Protocol == ProtocolType.TCP),
            "tcp.dstport" or "dstport" => p => ComparePort(p.DestinationPort, value, op, p.Protocol == ProtocolType.TCP),
            "udp.srcport" => p => ComparePort(p.SourcePort, value, op, p.Protocol == ProtocolType.UDP),
            "udp.dstport" => p => ComparePort(p.DestinationPort, value, op, p.Protocol == ProtocolType.UDP),

            "tcp.port" => p => (ComparePort(p.SourcePort, value, op, true) || ComparePort(p.DestinationPort, value, op, true))
                                && p.Protocol == ProtocolType.TCP,
            "udp.port" => p => (ComparePort(p.SourcePort, value, op, true) || ComparePort(p.DestinationPort, value, op, true))
                                && p.Protocol == ProtocolType.UDP,

            "protocol" or "proto" => p => CompareProtocol(p.Protocol, value, op),

            "http.host" => p => p.HttpInfo != null && CompareString(p.HttpInfo.Host, value, op),
            "http.url" => p => p.HttpInfo != null && CompareString(p.HttpInfo.Url, value, op),
            "http.method" => p => p.HttpInfo != null && CompareString(p.HttpInfo.Method, value, op),

            "arp.src.proto_ipv4" or "arp.sender.ip" => p => p.ArpHeader != null && CompareIp(p.ArpHeader.SenderIp, value, op),
            "arp.dst.proto_ipv4" or "arp.target.ip" => p => p.ArpHeader != null && CompareIp(p.ArpHeader.TargetIp, value, op),

            "eth.src" or "eth.src_mac" => p => CompareMac(p.SourceMac, value, op),
            "eth.dst" or "eth.dst_mac" => p => CompareMac(p.DestinationMac, value, op),

            "frame.len" or "length" => p => CompareInt(p.Length, value, op),

            _ => _ => true
        };
    }

    private static bool CompareIp(IPAddress? ip, string value, string op)
    {
        if (ip == null) return false;
        if (value == "*") return true;

        if (value.EndsWith(".*"))
        {
            string prefix = value.Substring(0, value.Length - 2);
            bool startsWith = ip.ToString().StartsWith(prefix + ".");
            return op == "==" ? startsWith : !startsWith;
        }

        if (IPAddress.TryParse(value, out var targetIp))
        {
            bool equal = ip.Equals(targetIp);
            return op switch
            {
                "==" => equal,
                "!=" => !equal,
                _ => false
            };
        }

        return false;
    }

    private static bool ComparePort(int port, string value, string op, bool condition)
    {
        if (!condition) return false;
        if (int.TryParse(value, out int targetPort))
        {
            return op switch
            {
                "==" => port == targetPort,
                "!=" => port != targetPort,
                ">" => port > targetPort,
                "<" => port < targetPort,
                ">=" => port >= targetPort,
                "<=" => port <= targetPort,
                _ => false
            };
        }
        return false;
    }

    private static bool CompareProtocol(ProtocolType protocol, string value, string op)
    {
        bool equal = protocol.ToString().Equals(value, StringComparison.OrdinalIgnoreCase);
        return op switch
        {
            "==" => equal,
            "!=" => !equal,
            "contains" => protocol.ToString().Contains(value, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool CompareString(string? str, string value, string op)
    {
        if (str == null) return false;
        return op switch
        {
            "==" => str.Equals(value, StringComparison.OrdinalIgnoreCase),
            "!=" => !str.Equals(value, StringComparison.OrdinalIgnoreCase),
            "contains" => str.Contains(value, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool CompareMac(System.Net.NetworkInformation.PhysicalAddress? mac, string value, string op)
    {
        if (mac == null) return false;
        bool equal = mac.ToString().Equals(value, StringComparison.OrdinalIgnoreCase) ||
                     mac.ToString().Replace("-", "").Equals(value.Replace(":", "").Replace("-", ""), StringComparison.OrdinalIgnoreCase);
        return op switch
        {
            "==" => equal,
            "!=" => !equal,
            _ => false
        };
    }

    private static bool CompareInt(int num, string value, string op)
    {
        if (int.TryParse(value, out int target))
        {
            return op switch
            {
                "==" => num == target,
                "!=" => num != target,
                ">" => num > target,
                "<" => num < target,
                ">=" => num >= target,
                "<=" => num <= target,
                _ => false
            };
        }
        return false;
    }
}
