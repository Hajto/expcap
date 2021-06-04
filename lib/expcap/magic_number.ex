defimpl String.Chars, for: ExPcap.MagicNumber do
  @doc """
  Returns a human readable representation of the magic number.
  """
  @spec to_string(ExPcap.MagicNumber.t()) :: String.t()
  def to_string(magic_number) do
    """
    magic number:         0x#{magic_number.magic |> Integer.to_string(16) |> String.downcase()}
      nanoseconds?        #{magic_number.nanos}
      reverse bytes?      #{magic_number.reverse_bytes}
    """
    |> String.trim()
  end
end

defmodule ExPcap.MagicNumber do
  @moduledoc """
  This module represents a 'magic number' from a pcap header. The magic number
  not only contains a known value, but the value indicates the order in which
  bytes should be read AND whether or not datetimes use milliseconds or
  nanoseconds.
  """

  defstruct reverse_bytes: false,
            nanos: false,
            magic: 0x00000000

  @type t :: %ExPcap.MagicNumber{
          reverse_bytes: boolean,
          nanos: boolean,
          magic: non_neg_integer
        }

  @bytes_in_magic 4

  @doc """
  Returns the number of bytes contained in the magic number.
  """
  @spec bytes_in_magic() :: non_neg_integer
  def bytes_in_magic() do
    @bytes_in_magic
  end

  @doc """
  Returns a magic number that indicates that the bytes need to be reversed when
  read and that datetimes are in milliseconds.
  """
  @spec magic_number(0xD4, 0xC3, 0xB2, 0xA1) :: ExPcap.MagicNumber.t()
  def magic_number(0xD4, 0xC3, 0xB2, 0xA1) do
    %ExPcap.MagicNumber{
      reverse_bytes: true,
      nanos: false,
      magic: 0xD4C3B2A1
    }
  end

  @doc """
  Returns a magic number that indicates that the bytes do not need to be
  reversed when read and that datetimes are in milliseconds.
  """
  @spec magic_number(0xA1, 0xB2, 0xC3, 0xD4) :: ExPcap.MagicNumber.t()
  def magic_number(0xA1, 0xB2, 0xC3, 0xD4) do
    %ExPcap.MagicNumber{
      reverse_bytes: false,
      nanos: false,
      magic: 0xA1B2C3D4
    }
  end

  @doc """
  Returns a magic number that indicates that the bytes do not need to be
  reversed when read and that datetimes are in nanoseconds.
  """
  @spec magic_number(0xA1, 0xB2, 0x3C, 0x4D) :: ExPcap.MagicNumber.t()
  def magic_number(0xA1, 0xB2, 0x3C, 0x4D) do
    %ExPcap.MagicNumber{
      reverse_bytes: false,
      nanos: true,
      magic: 0xA1B2C3D4
    }
  end

  @doc """
  Returns a magic number that indicates that the bytes need to be reversed when
  read and that datetimes are in nanoseconds.
  """
  @spec magic_number(0x4D, 0x3C, 0xB2, 0xA1) :: ExPcap.MagicNumber.t()
  def magic_number(0x4D, 0x3C, 0xB2, 0xA1) do
    %ExPcap.MagicNumber{
      reverse_bytes: true,
      nanos: true,
      magic: 0xA1B2C3D4
    }
  end

  @doc """
  This reads the bytes of the magic number and matches them with the appropriate
  interpretation of the magic number.
  """
  @spec read_magic(binary) :: ExPcap.MagicNumber.t()
  def read_magic(data) do
    <<
      magic1::unsigned-integer-size(8),
      magic2::unsigned-integer-size(8),
      magic3::unsigned-integer-size(8),
      magic4::unsigned-integer-size(8)
    >> = data

    magic_number(magic1, magic2, magic3, magic4)
  end

  @doc """
  Reads the magic number from the file passed in.
  """
  @spec from_file(IO.device()) :: ExPcap.MagicNumber.t()
  def from_file(f) do
    f |> IO.binread(@bytes_in_magic) |> read_magic
  end
end
