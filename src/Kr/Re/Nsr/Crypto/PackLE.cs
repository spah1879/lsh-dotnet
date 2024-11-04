namespace Kr.Re.Nsr.Crypto
{
  /// <summary>
  /// 바이트 배열을 리틀 엔디안 형식의 정수로 변환하기 위한 도구
  /// </summary>
  public static class PackLE
  {
    /// <summary>바이트 배열을 unsigned integer 로 변환</summary>
    /// <param name="inBytes">변환할 바이트 배열</param>
    /// <param name="offset">시작 오프셋</param>
    /// <returns>
    /// 변환된 unsigned integer
    /// </returns>
    public static uint ToU32(byte[] inBytes, int offset)
    {

      uint result = (uint)(inBytes[offset] & 0xff);
      result |= (uint)(inBytes[++offset] & 0xff) << 8;
      result |= (uint)(inBytes[++offset] & 0xff) << 16;
      result |= (uint)(inBytes[++offset] & 0xff) << 24;

      return result;
    }

    /// <summary>바이트 배열을 unsigned integer 로 변환</summary>
    /// <param name="inBytes">변환할 바이트 배열</param>
    /// <param name="inOff">바이트 배열의 시작 오프셋</param>
    /// <param name="outBytes">unsigned integer 배열</param>
    /// <param name="outOff">unsigned integer 배열의 시작 오프셋</param>
    /// <param name="length">변환할 unsigned integer 의 길이</param>
    public static void ToU32(byte[] inBytes, int inOff, uint[] outBytes, int outOff, int length)
    {

      for (int idx = outOff; idx < outOff + length; idx++, inOff++)
      {
        outBytes[idx] = (uint)inBytes[inOff] & 0xff;
        outBytes[idx] |= (uint)(inBytes[++inOff] & 0xff) << 8;
        outBytes[idx] |= (uint)(inBytes[++inOff] & 0xff) << 16;
        outBytes[idx] |= (uint)(inBytes[++inOff] & 0xff) << 24;
      }

    }

    /// <summary>바이트 배열을 unsigned long 으로 변환</summary>
    /// <param name="inBytes">변환할 바이트 배열</param>
    /// <param name="offset">시작 오프셋</param>
    /// <returns>
    /// 변환된 unsigned integer
    /// </returns>
    public static ulong ToU64(byte[] inBytes, int offset)
    {

      ulong result = (ulong)(inBytes[offset] & 0xff);
      result |= (ulong)(inBytes[++offset] & 0xff) << 8;
      result |= (ulong)(inBytes[++offset] & 0xff) << 16;
      result |= (ulong)(inBytes[++offset] & 0xff) << 24;
      result |= (ulong)(inBytes[++offset] & 0xff) << 32;
      result |= (ulong)(inBytes[++offset] & 0xff) << 40;
      result |= (ulong)(inBytes[++offset] & 0xff) << 48;
      result |= (ulong)(inBytes[++offset] & 0xff) << 56;

      return result;
    }

    /// <summary>바이트 배열을 unsigned long 으로 변환</summary>
    /// <param name="inBytes">변환할 바이트 배열</param>
    /// <param name="inOff">바이트 배열의 시작 오프셋</param>
    /// <param name="outBytes">unsigned long 배열</param>
    /// <param name="outOff">unsigned long 배열의 시작 오프셋</param>
    /// <param name="length">변환할 unsigned long 의 길이</param>
    public static void ToU64(byte[] inBytes, int inOff, ulong[] outBytes, int outOff, int length)
    {

      for (int idx = outOff; idx < outOff + length; idx++, inOff++)
      {
        outBytes[idx] = (ulong)inBytes[inOff] & 0xff;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 8;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 16;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 24;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 32;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 40;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 48;
        outBytes[idx] |= (ulong)(inBytes[++inOff] & 0xff) << 56;
      }

    }
  }
}
