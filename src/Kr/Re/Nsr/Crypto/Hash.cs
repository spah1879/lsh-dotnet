namespace Kr.Re.Nsr.Crypto
{
  /// <summary>
  /// LSH256, LSH512 의 상위 클래스, 해시 함수 구현을 위한 공통 인터페이스를 포함하는 클래스이다.
  /// </summary>
  public abstract class Hash
  {
    /// <summary>LSH 알고리즘 명세</summary>
    public enum Algorithm
    {
      /// <summary>LSH-256-224 알고리즘 명세</summary>
      LSH256_224,

      /// <summary>LSH-256-256 알고리즘 명세</summary>
      LSH256_256,

      /// <summary>LSH-512-224 알고리즘 명세</summary>
      LSH512_224,

      /// <summary>LSH-512-256 알고리즘 명세</summary>
      LSH512_256,

      /// <summary>LSH-512-384 알고리즘 명세</summary>
      LSH512_384,

      /// <summary>LSH-512-512 알고리즘 명세</summary>
      LSH512_512
    }

    /// <summary>같은 출력길이를 가지는 객체를 만들어 리턴한다.</summary>
    /// <returns>LSH Digest 객체</returns>
    public abstract Hash NewInstance();

    /// <summary>내부 계산에 사용되는 메시지 블록 비트 길이를 리턴한다.</summary>
    /// <returns>메시지 블록 비트 길이</returns>
    public abstract int GetBlockSize();

    /// <summary>해시 출력 길이를 리턴한다.</summary>
    /// <returns>해시 출력 길이 (비트 단위)</returns>
    public abstract int GetOutlenBits();

    /// <summary>내부 상태를 초기화하여 새로은 message digest를 계산할 준비를 한다.</summary>
    public abstract void Reset();

    /// <summary>message digest를 계산할 데이터를 처리한다.</summary>
    /// <param name="data">message digest를 계산할 데이터</param>
    /// <param name="offset">데이터 배열의 시작 오프셋</param>
    /// <param name="lenBits">데이터의 길이(비트 단위)</param>
    public abstract void Update(byte[] data, int offset, int lenBits);

    /// <summary>message digest를 계산한다</summary>
    /// <returns>계산된 message digest 값</returns>
    public abstract byte[] DoFinal();

    /// <summary>message digest를 계산할 데이터를 처리한다.</summary>
    /// <param name="data">message digest를 계산할 데이터</param>
    public void Update(byte[] data)
    {
      if (data != null)
      {
        Update(data, 0, data.Length * 8);
      }
    }

    /// <summary>data를 추가하여 최종 message digest를 계산한다.</summary>
    /// <param name="data">message digest를 계산할 데이터</param>
    /// <param name="offset">데이터 배열의 시작 오프셋</param>
    /// <param name="lenBits">데이터의 길이 (비트 단위)</param>
    /// <returns>계산된 message digest 값</returns>
    public byte[] DoFinal(byte[] data, int offset, int lenBits)
    {
      if (data != null && lenBits > 0)
      {
        Update(data, offset, lenBits);
      }

      return DoFinal();
    }

    /// <summary>data를 추가하여 최종 message digest를 계산한다.</summary>
    /// <param name="data">최종 data</param>
    /// <returns>계산된 message digest</returns>
    public byte[] DoFinal(byte[] data)
    {
      if (data != null)
      {
        Update(data);
      }

      return DoFinal();
    }


    /// <summary>algorithm에 해당하는 해시함수 객체 리턴</summary>
    /// <param name="algorithm">알고리즘</param>
    /// <returns>해시함수 객체</returns>
    public static Hash GetInstance(Algorithm algorithm)
    {
      Hash lsh;

      switch (algorithm)
      {
        case Algorithm.LSH256_224:
          lsh = new LSH256(224);
          break;

        case Algorithm.LSH256_256:
          lsh = new LSH256(256);
          break;

        case Algorithm.LSH512_224:
          lsh = new LSH512(224);
          break;

        case Algorithm.LSH512_256:
          lsh = new LSH512(256);
          break;

        case Algorithm.LSH512_384:
          lsh = new LSH512(384);
          break;

        case Algorithm.LSH512_512:
          lsh = new LSH512(512);
          break;

        default:
          throw new ArgumentException("Unsupported Algorithm");
      }

      return lsh;
    }

    /// <summary>algorithm을 이용하여 해시 계산</summary>
    /// <param name="algorithm">알고리즘</param>
    /// <param name="data">해시값을 계산할 데이터</param>
    /// <returns>계산된 message digest 값</returns>
    public static byte[] Digest(Algorithm algorithm, byte[] data)
    {
      return Digest(algorithm, data, 0, data == null ? 0 : data.Length << 3);
    }

    /// <summary>algorithm을 이용하여 해시 계산</summary>
    /// <param name="algorithm">알고리즘</param>
    /// <param name="data">해시값을 계산할 데이터</param>
    /// <param name="offset">데이터 시작 오프셋</param>
    /// <param name="lenBits">데이터 길이, 비트 단위</param>
    /// <returns>계산된 message digest 값</returns>
    public static byte[] Digest(Algorithm algorithm, byte[] data, int offset, int lenBits)
    {
      Hash lsh = Hash.GetInstance(algorithm);
      lsh.Update(data, offset, lenBits);
      return lsh.DoFinal();
    }

    /// <summary>LSH-wordLenBits-hashLenBits 알고리즘을 이용하여 해시 계산</summary>
    /// <param name="wordLenBits">워드 길이, 비트 단위, 256 or 512</param>
    /// <param name="hashLenBits">출력 길이, 비트 단위, 1 ~ wordLenBits</param>
    /// <param name="data">해시를 계산할 데이터</param>
    /// <returns>해시값</returns>
    public static byte[] Digest(int wordLenBits, int hashLenBits, byte[] data)
    {
      int lenBits = data == null ? 0 : data.Length * 8;
      return Digest(wordLenBits, hashLenBits, data, 0, lenBits);
    }

    /// <summary>LSH-wordLenBits-hashLenBits 알고리즘을 이용하여 해시 계산</summary>
    /// <param name="wordLenBits">워드 길이, 비트 단위, 256 or 512</param>
    /// <param name="hashLenBits">출력 길이, 비트 단위, 1 ~ wordLenBits</param>
    /// <param name="data">해시를 계산할 데이터</param>
    /// <param name="offset">데이터 시작 오프셋</param>
    /// <param name="lenBits">데이터 길이, 비트 단위</param>
    /// <returns>해시값</returns>
    public static byte[] Digest(int wordLenBits, int hashLenBits, byte[] data, int offset, int lenBits)
    {
      Hash lsh;

      switch (wordLenBits)
      {
        case 256:
          lsh = new LSH256(hashLenBits);
          break;

        case 512:
          lsh = new LSH512(hashLenBits);
          break;

        default:
          throw new ArgumentException("Unsupported wordLenBits");
      }

      lsh.Update(data, offset, lenBits);

      return lsh.DoFinal();
    }

  }
}
