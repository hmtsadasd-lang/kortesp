import sys

with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'r') as f:
    c = f.read()

# Add debug output inside the loop
old = '''        const char* name = reinterpret_cast<const char*>(&buf[off + 0x28]);
        size_t nl = 0;
        while (nl < 256 && name[nl]) ++nl;
        if (nl == 0) continue;'''

new = '''        const char* name = reinterpret_cast<const char*>(&buf[off + 0x28]);
        size_t nl = 0;
        while (nl < 256 && name[nl]) ++nl;
        if (nl == 0) continue;
        printf("[DEBUG]   module %d: '%s'\\n", i, name);'''

if old in c:
    c = c.replace(old, new, 1)
    with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'w') as f:
        f.write(c)
    print('SUCCESS')
else:
    print('NOT FOUND')