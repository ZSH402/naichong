import sys
blocks = []
for i in range(200):
    blocks.append(bytearray(1024 * 1024))
    sys.stdout.write('.')
    sys.stdout.flush()
