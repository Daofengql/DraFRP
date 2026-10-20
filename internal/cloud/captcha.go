package cloud

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"strings"
	"time"
)

const captchaAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
const captchaCapacity = 4096
const captchaTTL = 2 * time.Minute

type captchaEntry struct {
	Digest    [32]byte
	ExpiresAt time.Time
}
type captchaChallenge struct {
	ID        string    `json:"captcha_id"`
	Image     string    `json:"image"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) captchaDigest(id, answer string) [32]byte {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write([]byte("drafrp-captcha-v1\n" + id + "\n" + strings.ToUpper(strings.TrimSpace(answer))))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func (s *Server) verifyCaptcha(id, answer string) bool {
	if s.cfg.CaptchaDisabled {
		return true
	}
	if len(id) != 32 {
		return false
	}
	s.captchaMu.Lock()
	entry, exists := s.captchas[id]
	delete(s.captchas, id) // Every attempt consumes authority, including wrong/empty answers.
	s.captchaMu.Unlock()
	if !exists || !now().Before(entry.ExpiresAt) || len(answer) > 64 {
		return false
	}
	got := s.captchaDigest(id, answer)
	return subtle.ConstantTimeCompare(got[:], entry.Digest[:]) == 1
}
func (s *Server) captcha(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	if s.cfg.CaptchaDisabled {
		apiErr(w, 404, "captcha_disabled", "captcha is disabled")
		return
	}
	if !s.allowRequest(r, "captcha", 30) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many captcha requests")
		return
	}
	challenge, err := s.newCaptcha()
	if err != nil {
		apiErr(w, 503, "captcha_unavailable", "captcha capacity is temporarily unavailable")
		return
	}
	writeJSON(w, 200, challenge)
}
func (s *Server) newCaptcha() (captchaChallenge, error) {
	// Answers and IDs use disjoint cryptographic bytes; publishing an ID or
	// image noise never reveals the random bytes used to choose the answer.
	var seed [512]byte
	entropy := s.captchaEntropy
	if entropy == nil {
		entropy = rand.Reader
	}
	if _, err := io.ReadFull(entropy, seed[:]); err != nil {
		return captchaChallenge{}, err
	}
	var code [6]byte
	for i := range code {
		code[i] = captchaAlphabet[int(seed[i])&31]
	}
	out := captchaChallenge{ID: base64.RawURLEncoding.EncodeToString(seed[6:30]), ExpiresAt: now().Add(captchaTTL)}
	img := renderCaptcha(string(code[:]), seed[30:])
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return captchaChallenge{}, err
	}
	out.Image = "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
	s.captchaMu.Lock()
	defer s.captchaMu.Unlock()
	if s.captchas == nil {
		s.captchas = make(map[string]captchaEntry)
	}
	for id, entry := range s.captchas {
		if !now().Before(entry.ExpiresAt) {
			delete(s.captchas, id)
		}
	}
	if len(s.captchas) >= captchaCapacity {
		return captchaChallenge{}, io.ErrShortBuffer
	}
	if _, collision := s.captchas[out.ID]; collision {
		return captchaChallenge{}, io.ErrNoProgress
	}
	s.captchas[out.ID] = captchaEntry{Digest: s.captchaDigest(out.ID, string(code[:])), ExpiresAt: out.ExpiresAt}
	return out, nil
}

// A small bundled bitmap alphabet keeps image generation local and independent
// of installed fonts, external services, SVG execution or platform libraries.
var captchaGlyphs = map[byte][7]byte{
	'A': {14, 17, 17, 31, 17, 17, 17}, 'B': {30, 17, 17, 30, 17, 17, 30}, 'C': {14, 17, 16, 16, 16, 17, 14}, 'D': {30, 17, 17, 17, 17, 17, 30},
	'E': {31, 16, 16, 30, 16, 16, 31}, 'F': {31, 16, 16, 30, 16, 16, 16}, 'G': {14, 17, 16, 23, 17, 17, 15}, 'H': {17, 17, 17, 31, 17, 17, 17},
	'J': {7, 2, 2, 2, 18, 18, 12}, 'K': {17, 18, 20, 24, 20, 18, 17}, 'L': {16, 16, 16, 16, 16, 16, 31}, 'M': {17, 27, 21, 21, 17, 17, 17},
	'N': {17, 25, 21, 19, 17, 17, 17}, 'P': {30, 17, 17, 30, 16, 16, 16}, 'Q': {14, 17, 17, 17, 21, 18, 13}, 'R': {30, 17, 17, 30, 20, 18, 17},
	'S': {15, 16, 16, 14, 1, 1, 30}, 'T': {31, 4, 4, 4, 4, 4, 4}, 'U': {17, 17, 17, 17, 17, 17, 14}, 'V': {17, 17, 17, 17, 17, 10, 4},
	'W': {17, 17, 17, 21, 21, 21, 10}, 'X': {17, 17, 10, 4, 10, 17, 17}, 'Y': {17, 17, 10, 4, 4, 4, 4}, 'Z': {31, 1, 2, 4, 8, 16, 31},
	'2': {14, 17, 1, 2, 4, 8, 31}, '3': {30, 1, 1, 14, 1, 1, 30}, '4': {2, 6, 10, 18, 31, 2, 2}, '5': {31, 16, 16, 30, 1, 1, 30},
	'6': {14, 16, 16, 30, 17, 17, 14}, '7': {31, 1, 2, 4, 8, 8, 8}, '8': {14, 17, 17, 14, 17, 17, 14}, '9': {14, 17, 17, 15, 1, 1, 14},
}

func renderCaptcha(code string, seed []byte) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 208, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 208; x++ {
			img.SetRGBA(x, y, color.RGBA{244, 247, 250, 255})
		}
	}
	for i := 0; i+2 < len(seed); i += 3 {
		x, y := int(seed[i])%208, int(seed[i+1])%64
		v := uint8(155 + int(seed[i+2])%65)
		img.SetRGBA(x, y, color.RGBA{v, v, v, 255})
	}
	for i := range code {
		glyph := captchaGlyphs[code[i]]
		x0, y0 := 14+i*31, 14+int(seed[i])%6
		ink := color.RGBA{uint8(25 + int(seed[i+6])%45), uint8(35 + int(seed[i+12])%45), uint8(55 + int(seed[i+18])%45), 255}
		for row, bits := range glyph {
			for col := 0; col < 5; col++ {
				if bits&(1<<uint(4-col)) != 0 {
					for dy := 0; dy < 4; dy++ {
						for dx := 0; dx < 4; dx++ {
							img.SetRGBA(x0+col*4+dx, y0+row*4+dy, ink)
						}
					}
				}
			}
		}
	}
	return img
}
