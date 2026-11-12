#pragma once
#include <cstddef>

namespace hide {
    bool alloc_rx(void* base, size_t image_size);
    bool launch_worker(void* worker);
    void stop_worker();
}