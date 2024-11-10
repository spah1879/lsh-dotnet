namespace Kr.Re.Nsr.Crypto
{
  public class HMac : Mac
  {
    private const byte IPAD = 0x36;
    private const byte OPAD = 0x5c;

    private readonly int blockSize;
    private readonly Hash digest;

    private readonly byte[] iKeyPad;
    private readonly byte[] oKeyPad;


    /// <summary>생성자</summary>
    /// <param name="md">MessageDigest 객체</param>
    public HMac(Hash md)
    {
      if (md == null)
      {
        throw new ArgumentException("md should not be null");
      }

      digest = md.NewInstance();
      blockSize = digest.GetBlockSize();

      iKeyPad = new byte[blockSize];
      oKeyPad = new byte[blockSize];
    }

    /// <summary>내부 상태 초기화</summary>
    /// <param name="key">비밀키</param>
    public override void Init(byte[] key)
    {
      if (key == null)
      {
        throw new ArgumentException("key should not be null");
      }

      if (key.Length > blockSize)
      {
        digest.Reset();
        key = digest.DoFinal(key);
      }

      Array.Fill(iKeyPad, IPAD);
      Array.Fill(oKeyPad, OPAD);
      for (int i = 0; i < key.Length; ++i)
      {
        iKeyPad[i] ^= key[i];
        oKeyPad[i] ^= key[i];
      }

      Reset();
    }

    /// <summary>해시 함수를 초기화하고 i_key_pad 를 hash 함수에 넣어둔다</summary>
    public override void Reset()
    {
      digest.Reset();
      digest.Update(iKeyPad);
    }

    /// <summary>MAC을 계산할 메시지를 hash 함수에 넣는다</summary>
    /// <param name="msg">추가할 메시지</param>
    public override void Update(byte[] msg)
    {
      if (msg == null)
      {
        return;
      }

      digest.Update(msg);
    }

    /// <summary>H(i_key_pad || msg) 를 계산하고, H(o_key_pad || H(i_key_pad || msg)) 를 계산한다</summary>
    /// <returns>MAC 값</returns>
    public override byte[] DoFinal()
    {
      byte[] result = digest.DoFinal();

      digest.Reset();
      digest.Update(oKeyPad);
      result = digest.DoFinal(result);

      Reset();

      return result;
    }

    public static byte[] Digest(Hash.Algorithm algorithm, byte[] key, byte[] msg)
    {
      Hash hash = Hash.GetInstance(algorithm);
      HMac hmac = new HMac(hash);
      hmac.Init(key);
      return hmac.DoFinal(msg);
    }
  }

}
