def cyclexor(string : String, key : String, pack : Bool = false) : String
  final = IO::Memory.new
  cycle = UInt8.new(0)
  raw = Slice(UInt8)
  string.each_byte do |byte|
    cycle = byte
    key.each_byte do |keybit|
      cycle = cycle ^ keybit
    end
    final.write_bytes(cycle, IO::ByteFormat::LittleEndian)
  end
  raw = final.to_slice
  pack ? raw.hexstring : String.new(raw)
end

# key = "jfasidofjoasdjfadsfajsdfijasifoasjiofdf"
# msg = "Hello World"
# puts("First: #{msg.bytes}")
# enc = cyclexor(msg, key)
# puts("Enc: #{enc}")
# dec = cyclexor(enc, key)
# puts("Dec: #{dec}")

