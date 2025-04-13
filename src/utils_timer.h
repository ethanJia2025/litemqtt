#ifndef _UTILS_TIMER_H_
#define _UTILS_TIMER_H_
 
 #include <stdint.h>
 
 typedef struct {
     uint32_t time;
 } utils_time_t;
 
 
 void utils_time_start(utils_time_t *timer);
 
 uint32_t utils_time_spend(utils_time_t *start);
 
 uint32_t utils_time_left(utils_time_t *end);
 
 uint32_t utils_time_is_expired(utils_time_t *timer);
 
 void utils_time_init(utils_time_t *timer);
 
 void utils_time_countdown_ms(utils_time_t *timer, uint32_t millisecond);
 
 uint32_t utils_time_get_ms(void);
 
 #endif 
 
 
 