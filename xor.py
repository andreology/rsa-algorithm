text = input("Enter text: ")
key = input("Enter Key: ")
n = len(text)
cipher = ""
for i in range(n):
  t = text[i]
  k = key[i% len(key)]
  x = ord(k) ^ ord(t)
  cipher += chr(x)
print( key, cipher, hexlify(text.encode()))