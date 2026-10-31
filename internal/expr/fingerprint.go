package expr

// ValidJA4 reports whether s is a JA4 TLS client fingerprint, such as
// t13d1516h2_8daaf6152771_02713d6af862: protocol t, q or d; TLS version 10
// to 13, s2, s3, d1 to d3 or 00; SNI d or i; two two-digit counts; the
// first and last ALPN characters; two 12-character lowercase hex hashes.
// See https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md.
// It allocates nothing: the edge runs it on every fingerprint header.
func ValidJA4(s string) bool {
	if len(s) != 36 || s[10] != '_' || s[23] != '_' {
		return false
	}
	switch s[0] {
	case 't', 'q', 'd':
	default:
		return false
	}
	switch v1, v2 := s[1], s[2]; v1 {
	case '1':
		if v2 < '0' || v2 > '3' {
			return false
		}
	case 's':
		if v2 != '2' && v2 != '3' {
			return false
		}
	case 'd':
		if v2 < '1' || v2 > '3' {
			return false
		}
	case '0':
		if v2 != '0' {
			return false
		}
	default:
		return false
	}
	if s[3] != 'd' && s[3] != 'i' {
		return false
	}
	for i := 4; i < 8; i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	for i := 8; i < 10; i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return isLowerHex(s[11:23]) && isLowerHex(s[24:])
}

// ValidJA3 reports whether s is a JA3 fingerprint: an MD5 hash written as
// 32 lowercase hex characters.
func ValidJA3(s string) bool { return len(s) == 32 && isLowerHex(s) }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHexLetter(c byte) bool { return 'a' <= c && c <= 'f' }

func isAlnum(c byte) bool { return isDigit(c) || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) && !isHexLetter(s[i]) {
			return false
		}
	}
	return true
}
