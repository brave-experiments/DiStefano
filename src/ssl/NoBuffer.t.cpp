#include "../doctest.h"
#include "NoBuffer.hpp"

static_assert(!NoBuffer::has_data());
static_assert(!NoBuffer::can_buffer());
