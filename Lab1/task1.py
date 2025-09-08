import os

lab1_dir = os.path.dirname(os.path.abspath(__file__))
fname = os.path.join(lab1_dir, 'infile.txt')
fname2 = os.path.join(lab1_dir, 'outfile.txt')

path = os.path.abspath(fname)
path2 = os.path.abspath(fname2)

print('copying ', path, 'to ', path2)

blocksize = 32
totalsize = 0
loopCount = 0

try:
    file = open(fname, 'rb')
    file2 = open(fname2, 'wb')
    print('Files opened successfully.')

    while True:
        data = file.read(blocksize)
        if not data:
            break
        loopCount += 1
        file2.write(data)
        totalsize += len(data)
    file.close()
    file2.close()
    print(f'Total bytes copied: {totalsize}\nOver {loopCount} loops')
except Exception as e:
    print(f'Error: {e}')

def copy_text_file(src, dst, blocksize=16):
    """Copy a text file using character streams in blocks of blocksize characters."""
    totalsize = 0
    loopCount = 0
    try:
        with open(src, 'r', encoding='utf-8') as file, open(dst, 'w', encoding='utf-8') as file2:
            print(f'copying {os.path.abspath(src)} to {os.path.abspath(dst)} (text mode)')
            while True:
                data = file.read(blocksize)
                if not data:
                    break
                loopCount += 1
                file2.write(data)
                totalsize += len(data)
        print(f'Total characters copied: {totalsize}\nOver {loopCount} loops (text mode)')
    except Exception as e:
        print(f'Error (text mode): {e}')

# Example usage for character stream copy
copy_text_file(fname, fname2, blocksize=16)
