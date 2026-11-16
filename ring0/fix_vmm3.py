import sys

with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'r') as f:
    c = f.read()

old = '''    printf("[DEBUG] module_base: looking for '%s'
", image_name);
    printf("[DEBUG]   got=%lu count=%u stride=%zu
", got, count, stride);

    const size_t wl = strlen(image_name);
    if (!wl || wl >= 0x100) return false;

    printf("[DEBUG] module_base: looking for '%s'\\n", image_name);'''

new = '''    const size_t wl = strlen(image_name);
    if (!wl || wl >= 0x100) return false;

    printf("[DEBUG] module_base: looking for '%s'\\n", image_name);'''

if old in c:
    c = c.replace(old, new, 1)
    with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'w') as f:
        f.write(c)
    print('SUCCESS')
else:
    print('NOT FOUND')
    # Show what's around line 388
    with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'r') as f:
        lines = f.readlines()
    for i, line in enumerate(lines[388:400], start=389):
        print(f'{i}: {line}', end='')