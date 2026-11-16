import sys

with open('C:\\dev\\fortesp\\ring0\\src\\vmm.cpp', 'r') as f:
    c = f.read()

old = '''    size_t stride = (buf.size() - header) / count;
    if (!stride || stride < 0x28) stride = 296;

    const size_t wl = strlen(image_name);'''

new = '''    size_t stride = (got - header) / count;
    if (!stride || stride < 0x28) stride = 296;

    printf("[DEBUG] module_base: looking for '%s'\n", image_name);
    printf("[DEBUG]   got=%lu count=%u stride=%zu\n", got, count, stride);

    const size_t wl = strlen(image_name);'''

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
    for i, line in enumerate(lines[384:392], start=385):
        print(f'{i}: {line}', end='')