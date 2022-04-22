

proc lpwstrc(bytes: array[MAX_PATH, WCHAR]): string =
  result = newString(bytes.len)
  for i in bytes:
    result &= cast[char](i)
  result = strip(result, chars = {cast[char](0)})

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)
