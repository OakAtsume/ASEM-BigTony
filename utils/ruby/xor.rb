def cyclexor(string, key)
  bytes = string.bytes
  keybits = key.bytes
  cycle = 0
  out = []
  bytes.each do |byte|
    cycle = byte
    keybits.each do |bit|
      cycle = cycle ^ bit
    end
    out.push(cycle)
  end
  return out
end

# key = "jfasidofjoasdjfadsfajsdfijasifoasjiofdf"
# msg = "Hello World"
# puts("First: #{msg.bytes}")
# enc = cyclexor(msg, key)
# puts("Enc: #{enc}")
# dec = cyclexor(enc.pack("C*"), key)
# puts("Dec: #{dec}")

