using System.Buffers.Binary;
using System.Text;

namespace BridgeToFreedom.Services;

/// <summary>
/// Binary protocol matching the Go adapter/helper protocol exactly.
/// Wire format: [1B type][4B streamID BE][4B seqID BE][payload...]
/// </summary>
public static class Protocol
{
    // Control messages (streamID = 0)
    public const byte MsgHello    = 0x01;
    public const byte MsgHelloOK  = 0x02;
    public const byte MsgHelloErr = 0x03;
    public const byte MsgPeerConn = 0x04;
    public const byte MsgPeerGone = 0x05;
    public const byte MsgSync     = 0x06;
    public const byte MsgPing     = 0xF0;
    public const byte MsgPong     = 0xF1;

    // Stream messages (streamID > 0)
    public const byte MsgOpen     = 0x10;
    public const byte MsgOpenOK   = 0x11;
    public const byte MsgOpenFail = 0x12;
    public const byte MsgData     = 0x20;
    public const byte MsgFin      = 0x21;
    public const byte MsgRst      = 0x22;

    // Stream-ID layout (uint32, big-endian on the wire):
    //   bits 31..24  helperShortID (1..255; 0 = unassigned / legacy)
    //   bit  23      PROBE flag (1 = synthetic end-to-end-connectivity probe)
    //   bits 22..0   localID (helper-side allocator, ~8.4 M values per helper)
    // The adapter recognises StreamProbeFlag on OPEN and synthesises an
    // HTTP/1.1 200 OK response without dialling its configured target.
    public const int  StreamHelperShortIDShift = 24;
    public const uint StreamProbeFlag          = 0x00800000u;
    public const uint StreamLocalIDMask        = 0x007FFFFFu;

    public static bool IsProbe(uint streamId) => (streamId & StreamProbeFlag) != 0;
    public static byte HelperShortIdOf(uint streamId) => (byte)(streamId >> StreamHelperShortIDShift);

    public static string MsgName(byte type) => type switch
    {
        MsgHello    => "HELLO",
        MsgHelloOK  => "HELLO_OK",
        MsgHelloErr => "HELLO_ERR",
        MsgPeerConn => "PEER_CONN",
        MsgPeerGone => "PEER_GONE",
        MsgSync     => "SYNC",
        MsgPing     => "PING",
        MsgPong     => "PONG",
        MsgOpen     => "OPEN",
        MsgOpenOK   => "OPEN_OK",
        MsgOpenFail => "OPEN_FAIL",
        MsgData     => "DATA",
        MsgFin      => "FIN",
        MsgRst      => "RST",
        _ => $"0x{type:X2}"
    };

    public static byte[] Encode(byte type, uint streamId, byte[]? payload = null)
        => Encode(type, streamId, 0u, payload);

    public static byte[] Encode(byte type, uint streamId, uint seqId, byte[]? payload = null)
    {
        var p = payload ?? [];
        var buf = new byte[9 + p.Length];
        buf[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(1), streamId);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(5), seqId);
        if (p.Length > 0) p.CopyTo(buf, 9);
        return buf;
    }

    public static (byte Type, uint StreamId, uint SeqId, byte[] Payload) Decode(byte[] data)
    {
        if (data.Length < 9) throw new InvalidDataException("frame too short");
        var type = data[0];
        var streamId = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(1));
        var seqId = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(5));
        var payload = data.Length > 9 ? data[9..] : [];
        return (type, streamId, seqId, payload);
    }

    public static (string OwnId, string PeerId, string IamToken, byte HelperShortId) DecodeHelloOK(byte[] payload)
    {
        int off = 0;
        var ownId = ReadLenPrefixed(payload, ref off);
        var peerId = ReadLenPrefixed(payload, ref off);
        var iamToken = ReadLenPrefixed(payload, ref off);
        // Optional trailing 1-byte helperShortId (multi-helper mode). When the
        // cloud function assigns this helper a unique 1..255 ID, it appends
        // it here; the helper stamps it into the top byte of every streamID
        // it allocates so the adapter can route per-stream frames back to us.
        byte helperShortId = (byte)(off < payload.Length ? payload[off] : 0);
        return (ownId, peerId, iamToken, helperShortId);
    }

    /// <summary>
    /// PEER_CONN: [2B len][peerId][2B len][iamToken][1B helperShortId?]. In the
    /// helper-bound direction (v5) the optional trailing byte is this helper's
    /// adapter-confirmed shortId (0 = none).
    /// </summary>
    public static (string PeerId, string IamToken, byte HelperShortId) DecodePeerConn(byte[] payload)
    {
        int off = 0;
        var peerId = ReadLenPrefixed(payload, ref off);
        var iamToken = ReadLenPrefixed(payload, ref off);
        byte sid = (byte)(off < payload.Length ? payload[off] : 0);
        return (peerId, iamToken, sid);
    }

    /// <summary>PONG: [2B len][iamToken][1B helperShortId?] (trailing byte v5, helper-bound).</summary>
    public static (string IamToken, byte HelperShortId) DecodePong(byte[] payload)
    {
        int off = 0;
        var token = ReadLenPrefixed(payload, ref off);
        byte sid = (byte)(off < payload.Length ? payload[off] : 0);
        return (token, sid);
    }

    /// <summary>
    /// v5 PING/SYNC payload: the helper's current shortId claim (empty if 0), so
    /// cloud-function instances that don't know us re-register the same ID.
    /// </summary>
    public static byte[] EncodeClaim(byte helperShortId) =>
        helperShortId == 0 ? [] : [helperShortId];

    private static string ReadLenPrefixed(byte[] data, ref int off)
    {
        if (off + 2 > data.Length) throw new InvalidDataException("payload too short");
        var len = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(off));
        off += 2;
        if (off + len > data.Length) throw new InvalidDataException("payload truncated");
        var s = Encoding.UTF8.GetString(data, off, len);
        off += len;
        return s;
    }
}
