#include "utils_timer.h"

uint64_t port_uptime_ms(void);


void utils_time_start(utils_time_t *timer)
{
    if (!timer) {
        return;
    }

    timer->time = port_uptime_ms();
}

uint32_t utils_time_spend(utils_time_t *start)
{
    uint32_t now, res;

    if (!start) {
        return 0;
    }

    now = port_uptime_ms();
    res = now - start->time;
    return res;
}

uint32_t utils_time_left(utils_time_t *end)
{
    uint32_t now, res;

    if (!end) {
        return 0;
    }

    if (utils_time_is_expired(end)) {
        return 0;
    }

    now = port_uptime_ms();
    res = end->time - now;
    return res;
}

uint32_t utils_time_is_expired(utils_time_t *timer)
{
    uint32_t cur_time;

    if (!timer) {
        return 1;
    }

    cur_time = port_uptime_ms();
    /*
     *  WARNING: Do NOT change the following code until you know exactly what it do!
     *
     *  check whether it reach destination time or not.
     */
    if ((cur_time - timer->time) < (UINT32_MAX / 2)) {
        return 1;
    } else {
        return 0;
    }
}

void utils_time_init(utils_time_t *timer)
{
    if (!timer) {
        return;
    }

    timer->time = 0;
}

void utils_time_countdown_ms(utils_time_t *timer, uint32_t millisecond)
{
    if (!timer) {
        return;
    }

    timer->time = port_uptime_ms() + millisecond;
}

uint32_t utils_time_get_ms(void)
{
    return port_uptime_ms();
}

