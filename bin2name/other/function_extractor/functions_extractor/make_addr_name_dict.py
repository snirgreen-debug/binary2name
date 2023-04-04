import os

def removesuffix(text, suffix):
    if text.endswith(suffix):
        return text[:-len(suffix)]
    else:
        return text

cwd = os.getcwd()

filenames = []

for r, ds, fs in os.walk(cwd):
    for f in fs:
        if "sub_0x" not in f:
            continue
        t = f.split("sub_0x")
        t[1] = removesuffix(("sub_" + t[1].upper()), ".TXT")
        filenames.append((t[1], t[0]))

map = dict(filenames)
print(map)