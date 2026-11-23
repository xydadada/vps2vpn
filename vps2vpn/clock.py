"""The calendar that monthly traffic resets follow.

The owner may pick a time zone in the panel (setting `time_zone`): "UTC+8" style offsets, or an IANA name such as
"Asia/Shanghai" where the system has the zone database. Empty means the server's own clock, as before. A reset
day past the end of a month (29-31) falls on that month's last day.
"""
import calendar
import datetime as dt
import re
import threading
import time

_OFFSET = re.compile(r'UTC(?:([+-])(\d{1,2})(?::([0-5]\d))?)?')
_lock = threading.Lock()
_cached = (0.0, None, None)          # (read at, name, tzinfo or None)
_gen = 0                             # bumped by forget(): a reading begun before it is not kept
_TTL = 30


def parse(name):
    """tzinfo for a setting value; None for '' (the server's clock). Raises ValueError for anything else."""
    name = str(name or '').strip()
    if not name:
        return None
    m = _OFFSET.fullmatch(name)
    if m:
        if not m.group(1):
            return dt.timezone.utc
        hours, minutes = int(m.group(2)), int(m.group(3) or 0)
        if hours > 14 or (hours == 14 and minutes):
            raise ValueError('time zone offset too large')
        delta = dt.timedelta(hours=hours, minutes=minutes)
        return dt.timezone(-delta if m.group(1) == '-' else delta, name)
    if not re.fullmatch(r'[A-Za-z]+(?:/[A-Za-z0-9_+-]+){1,2}', name):
        raise ValueError('unknown time zone')
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        raise ValueError('unknown time zone') from None


def valid(name):
    """The setting as it should be stored, or None when it cannot be used here."""
    name = str(name or '').strip()
    try:
        parse(name)
    except ValueError:
        return None
    return name


def zone():
    """The owner's time zone (None = the server's clock). Re-read from the settings at most every 30 s."""
    global _cached
    now = time.monotonic()
    with _lock:
        at, name, tz = _cached
        gen = _gen
    if at and now - at < _TTL:
        return tz
    try:
        from . import db
        name = db.settings().get('time_zone') or ''
    except Exception:
        # The database busy for a moment: this once on the server's clock (or the last zone read), but not
        # remembered for 30 s.
        return tz if at else None
    try:
        tz = parse(name)
    except ValueError:
        tz = None                    # a setting this system cannot read: the server's clock, as the panel says
    with _lock:
        if _gen == gen:
            _cached = (now, name, tz)
    return tz


def forget():
    """Call after the setting changes, so the next reading uses it."""
    global _cached, _gen
    with _lock:
        _gen += 1
        _cached = (0.0, None, None)


def local(ts=None):
    ts = time.time() if ts is None else ts
    tz = zone()
    if tz is None:
        return time.localtime(ts)
    return dt.datetime.fromtimestamp(ts, tz).timetuple()


def month(ts=None):
    t = local(ts)
    return '%04d-%02d' % (t.tm_year, t.tm_mon)


def day_in(reset_day, year, mon):
    """The day a reset on `reset_day` falls on in that month (31 -> 30 in April, 28 or 29 in February)."""
    return min(int(reset_day), calendar.monthrange(year, mon)[1])


def reached(reset_day, ts=None):
    """True from this month's reset day on."""
    t = local(ts)
    return bool(reset_day) and t.tm_mday >= day_in(reset_day, t.tm_year, t.tm_mon)


def period_start(reset_day, ts=None):
    """(year, month, day) of the reset that began the current period."""
    t = local(ts)
    y, m = t.tm_year, t.tm_mon
    if t.tm_mday < day_in(reset_day, y, m):
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return y, m, day_in(reset_day, y, m)


def midnight(year, mon, day):
    """Seconds since the epoch at 00:00 of that day in the owner's time zone."""
    tz = zone()
    if tz is None:
        return int(time.mktime((year, mon, day, 0, 0, 0, 0, 0, -1)))
    return int(dt.datetime(year, mon, day, tzinfo=tz).timestamp())


def next_reset(reset_day, ts=None):
    """When the next monthly reset happens (0 = never)."""
    if not reset_day:
        return 0
    t = local(ts)
    y, m = t.tm_year, t.tm_mon
    if t.tm_mday >= day_in(reset_day, y, m):
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return midnight(y, m, day_in(reset_day, y, m))
