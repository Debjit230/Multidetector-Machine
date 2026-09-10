#include <Arduino.h>
#include <stdbool.h>
int __wrap_ieee80211_raw_frame_sanity_check(int ifx, const void *buffer, int len, bool auto_seq) {
  (void)ifx; (void)buffer; (void)len; (void)auto_seq;
  return 0;
}