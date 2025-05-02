def dump_meminfo : Hash(String, Int64)
  meminfo = {} of String => Int64

  File.each_line("/proc/meminfo") do |line|
    if match = line.match(/^(\w+):\s+(\d+)/)
      key = match[1]
      value = match[2].to_i64
      meminfo[key] = value
    end
  end
  return meminfo
end
