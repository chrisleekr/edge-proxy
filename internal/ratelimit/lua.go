package ratelimit

import (
	"crypto/sha1" //nolint:gosec // EVALSHA names scripts by SHA-1; not a security use
	"encoding/hex"
)

// Each script touches only KEYS[1] and reads time with TIME, so it is
// cluster-safe and immune to replica clock skew. ARGV is
// limit, period ms, burst, penalty ms. It returns allowed, remaining,
// reset ms, retry ms, server now ms and blocked-until ms, the fields of
// Result. The arithmetic matches Step exactly.
const luaHead = `
local function idiv(a, b)
  local q = math.floor(a / b)
  if q * b > a then q = q - 1 end
  return q
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + idiv(tonumber(t[2]), 1000)
local limit, period, burst, penalty = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local h = redis.call('HMGET', KEYS[1], 'a', 'b', 'c', 'x')
local set = h[1] ~= false
local a, b, c, x = tonumber(h[1]) or 0, tonumber(h[2]) or 0, tonumber(h[3]) or 0, tonumber(h[4]) or 0
if x > now then
  return {0, 0, x - now, x - now, now, x}
end
x = 0
local allowed, rem, reset, retry, ttl = 0, 0, 0, 0, 0
`

// luaTail stores the state. Numbers are formatted with %d because Lua's
// default number-to-string keeps only 14 significant digits.
const luaTail = `
if allowed == 0 and penalty > 0 then
  x = now + penalty
  retry = math.max(retry, penalty)
  reset = math.max(reset, penalty)
  ttl = math.max(ttl, penalty)
end
local f = '%d'
redis.call('HSET', KEYS[1], 'a', string.format(f, a), 'b', string.format(f, b), 'c', string.format(f, c), 'x', string.format(f, x))
redis.call('PEXPIRE', KEYS[1], math.max(ttl, 1))
local blocked = 0
if x > now then blocked = x end
return {allowed, rem, reset, retry, now, blocked}
`

var luaBody = [numAlgos]string{ //nolint:gosec // G101 matches "token" in Lua source; there are no credentials
	FixedWindow: `
local ws = now - now % period
if not set or a ~= ws then a = ws; b = 0 end
reset = ws + period - now
if b < limit then b = b + 1; allowed = 1; rem = limit - b else retry = reset end
ttl = reset
`,
	SlidingWindow: `
local ws = now - now % period
if set and a == ws then
elseif set and a == ws - period then c = b; b = 0
else b = 0; c = 0 end
a = ws
local w = idiv((period - (now - ws)) * 1000000, period)
local est = b + idiv(c * w + 999999, 1000000)
reset = ws + period - now
if est < limit then
  b = b + 1; allowed = 1; rem = limit - est - 1
else
  retry = reset
  if b >= limit then retry = retry + idiv(period + limit - 1, limit) end
end
ttl = reset + period
`,
	TokenBucket: `
local cap = burst * period
if not set then a = cap; b = now end
local el = math.max(now - b, 0)
local need = cap - a
if need <= 0 or el >= idiv(need + limit - 1, limit) then a = cap else a = a + el * limit end
b = now
if a >= period then
  a = a - period; allowed = 1; rem = idiv(a, period)
else
  retry = idiv(period - a + limit - 1, limit)
end
reset = idiv(cap - a + limit - 1, limit)
ttl = reset
`,
	LeakyBucket: `
local cap = burst * period
if not set then a = 0; b = now end
local el = math.max(now - b, 0)
if a <= 0 or el >= idiv(a + limit - 1, limit) then a = 0 else a = a - el * limit end
b = now
if a + period <= cap then
  a = a + period; allowed = 1; rem = idiv(cap - a, period)
else
  retry = idiv(a + period - cap + limit - 1, limit)
end
reset = idiv(a + limit - 1, limit)
ttl = reset
`,
}

type script struct{ src, sha string }

var scripts = func() (out [numAlgos]script) {
	for i, body := range luaBody {
		src := luaHead + body + luaTail
		sum := sha1.Sum([]byte(src)) //nolint:gosec // script name, see import
		out[i] = script{src: src, sha: hex.EncodeToString(sum[:])}
	}
	return out
}()
