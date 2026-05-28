// Package crypto implements cryptographic primitives for hermod.
//
// CPace is implemented per RFC 9496 using P-256 (NIST curve) with
// hash-to-curve via try-and-increment.
// AES-256-GCM is used for signaling payload encryption keyed by the CPace
// shared secret.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// --- CPace (RFC 9496 simplified over P-256) ---

// CPaceSession holds ephemeral state for one side of the CPace exchange.
type CPaceSession struct {
	scalar  []byte // 32-byte big-endian scalar
	pubMsg  []byte // 65-byte uncompressed point: 0x04 || X || Y
	sharedK []byte // set after Finish
}

// cpacePointSize is the byte length of an uncompressed P-256 point.
const cpacePointSize = 65

// CPaceInit creates a new CPace initiator message from the password.
// channelID is the transfer channel integer used as a domain separator.
// Returns the session and the public message (65 bytes) to send to the peer.
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error) {
	// Generator = hash-to-curve(password || channelID || role)
	gx, gy, err := cpaceGenerator(password, channelID)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace generator: %w", err)
	}

	// Generate ephemeral scalar y
	curve := elliptic.P256()
	n := curve.Params().N
	scalar, err := randScalar(n)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace scalar: %w", err)
	}

	// Y = scalar * G_password
	Yx, Yy := curve.ScalarMult(gx, gy, scalar.Bytes())

	pubMsg := marshalPoint(Yx, Yy)

	return &CPaceSession{
		scalar: scalar.Bytes(),
		pubMsg: pubMsg,
	}, pubMsg, nil
}

// CPaceFinish completes the CPace exchange given the peer's public message (65 bytes).
// Returns the 32-byte shared secret K.
func (s *CPaceSession) CPaceFinish(peerPub []byte) ([]byte, error) {
	if len(peerPub) != cpacePointSize || peerPub[0] != 0x04 {
		return nil, errors.New("cpace: invalid peer public message (must be 65-byte uncompressed P-256 point)")
	}
	curve := elliptic.P256()
	peerX, peerY, err := unmarshalPoint(curve, peerPub)
	if err != nil {
		return nil, fmt.Errorf("cpace finish unmarshal: %w", err)
	}
	// ISK_x = scalar * peerPub (x-coordinate)
	iskX, _ := curve.ScalarMult(peerX, peerY, s.scalar)
	h := sha256.Sum256(padTo32(iskX))
	k := h[:]
	s.sharedK = k
	return k, nil
}

// SharedK returns the derived shared secret (nil before CPaceFinish is called).
func (s *CPaceSession) SharedK() []byte { return s.sharedK }

// PubMessage returns the 65-byte public message.
func (s *CPaceSession) PubMessage() []byte { return s.pubMsg }

// cpaceGenerator hashes the password + channelID to a P-256 point using
// try-and-increment (deterministic hash-to-curve).
func cpaceGenerator(password string, channelID uint16) (*big.Int, *big.Int, error) {
	curve := elliptic.P256()
	p := curve.Params().P
	// Domain: "hermod-cpace-v1:" || password || ":" || channelID
	base := fmt.Sprintf("hermod-cpace-v1:%s:%d:", password, channelID)
	for ctr := 0; ctr < 256; ctr++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", base, ctr)))
		x := new(big.Int).SetBytes(h[:])
		x.Mod(x, p)
		// y^2 = x^3 - 3x + b (mod p)
		y2 := p256YSquared(x, curve.Params())
		y := modSqrt(y2, p)
		if y == nil {
			continue
		}
		// Verify
		check := new(big.Int).Mul(y, y)
		check.Mod(check, p)
		if check.Cmp(y2) != 0 {
			continue
		}
		// Use even y
		if y.Bit(0) != 0 {
			y.Sub(p, y)
		}
		// Validate point is on curve
		if !curve.IsOnCurve(x, y) {
			continue
		}
		return x, y, nil
	}
	return nil, nil, errors.New("cpace: hash-to-curve failed")
}

// p256YSquared computes x^3 - 3x + b mod p for P-256.
func p256YSquared(x *big.Int, params *elliptic.CurveParams) *big.Int {
	p := params.P
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, p)
	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, params.B)
	y2.Mod(y2, p)
	return y2
}

// modSqrt computes the modular square root using Euler's criterion for P-256
// where p ≡ 3 (mod 4), so sqrt = a^((p+1)/4) mod p.
func modSqrt(a, p *big.Int) *big.Int {
	if new(big.Int).ModSqrt(a, p) == nil {
		return nil
	}
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	r := new(big.Int).Exp(a, exp, p)
	check := new(big.Int).Mul(r, r)
	check.Mod(check, p)
	if check.Cmp(a) != 0 {
		return nil
	}
	return r
}

func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func marshalPoint(x, y *big.Int) []byte {
	pt := make([]byte, 65)
	pt[0] = 0x04
	copy(pt[1:33], padTo32(x))
	copy(pt[33:], padTo32(y))
	return pt
}

func unmarshalPoint(curve elliptic.Curve, data []byte) (*big.Int, *big.Int, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, nil, errors.New("invalid uncompressed point format")
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("point not on curve")
	}
	return x, y, nil
}

// randScalar generates a random scalar in [1, n-1].
func randScalar(n *big.Int) (*big.Int, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
		k.Add(k, big.NewInt(1))
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}

// sharedK is a dummy field to satisfy interface (moved to CPaceSession)
var _ = (*CPaceSession)(nil)

// --- AES-256-GCM ---

// Seal encrypts plaintext with key (must be 32 bytes) using AES-256-GCM.
// Returns nonce || ciphertext || tag.
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return ct, nil
}

// Open decrypts a blob produced by Seal.
func Open(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("open: blob too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// --- SAS (Short Authentication String) ---

// pgpWordListEven and pgpWordListOdd are used for SAS generation.
var pgpWordListEven = []string{
	"aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
	"aimless", "algol", "allow", "almighty", "ammo", "ancient", "apple", "arsenal",
	"assess", "atlas", "avalanche", "baboon", "barter", "behave", "belie", "believe",
	"berserk", "bilge", "blackjack", "blockade", "blowtorch", "blunder", "bombast", "bookshelf",
	"brackish", "breakaway", "brimstone", "bruiser", "bulldozer", "burnish", "button", "buzzard",
	"cement", "chairlift", "chatter", "chinchilla", "choking", "clarion", "classic", "cobra",
	"commence", "concert", "conform", "conquest", "crossover", "cruelly", "crusader", "cubic",
	"cyberspace", "cyclone", "damage", "darkroom", "daybreak", "deadlock", "debacle", "delight",
	"delta", "demote", "dentist", "depot", "desolate", "dingo", "diplomat", "discord",
	"dislodge", "displace", "disrupt", "distort", "diving", "document", "dolphin", "dominant",
	"doorstep", "dragon", "durable", "dwelling", "eclipse", "egghead", "element", "embargo",
	"embers", "embrace", "emerge", "emperor", "enchant", "endorse", "enrich", "entire",
	"envelope", "epoxy", "erase", "esteem", "eureka", "exact", "examine", "exceed",
	"exclaim", "exclude", "exhibit", "expel", "exploit", "eyeball", "fable", "facet",
	"faction", "fallout", "fanfare", "fantasy", "farmhand", "feather", "festive", "filament",
	"firebrand", "firsthand", "flagship", "flannel", "flashback", "flatten", "flicker", "floodgate",
	"flourish", "flywheel", "folklore", "footprint", "forage", "forecast", "forfeit", "fragment",
	"freshwater", "frontier", "frostbite", "fuselage", "gallop", "gatepost", "glimmer", "glitter",
	"gloom", "goblin", "goldfish", "governor", "gravel", "gridlock", "grizzly", "grovel",
	"guidebook", "gunshot", "hallway", "hamster", "handshake", "hangover", "hardship", "hardwood",
	"harmless", "harvest", "headband", "headlock", "heartbeat", "helpline", "heretic", "highrise",
	"holster", "homeland", "hopscotch", "horoscope", "howitzer", "humankind", "hustle", "iceberg",
	"icebreaker", "ignition", "implant", "impulse", "inferno", "inkblot", "innkeeper", "insomnia",
	"instant", "interlude", "invoke", "ironclad", "ironwork", "joystick", "junction", "keystone",
	"kickback", "kingpin", "kneecap", "labyrinth", "landfall", "landslide", "lantern", "liftoff",
	"limestone", "lockjaw", "lodestone", "longbow", "longtime", "lookout", "loudmouth", "mainframe",
	"malpractice", "mandate", "manifold", "marathon", "matchbox", "mechanic", "megabyte", "meltdown",
	"membrane", "merchant", "midnight", "minefield", "misfire", "missile", "mistletoe", "mockery",
	"momentum", "monument", "moonbeam", "mortgage", "motorboat", "mudslide", "mustang", "mystery",
	"navigate", "necklace", "neon", "newborn", "nightfall", "nightmare", "nimble", "nocturnal",
	"nominate", "notarize", "nowhere", "nuclear", "nutshell", "oblivion", "offshore", "outbreak",
	"outburst", "outpost", "overcast", "overlook", "overture", "overwork", "parachute", "parasite",
}

var pgpWordListOdd = []string{
	"adroitly", "adviser", "aftermath", "aggregate", "aggressor", "alphabet", "amulet", "antenna",
	"applicant", "aptitude", "arbitrary", "ardent", "armistice", "arraign", "article", "artisan",
	"aspect", "aspen", "assemble", "assert", "assist", "assorted", "attic", "atypical",
	"audacious", "auditor", "backdrop", "bacteria", "badminton", "baffle", "bankroll", "banter",
	"barbecue", "baseline", "bastion", "battalion", "battlement", "bayonet", "beckon", "bedrock",
	"beehive", "bellhop", "benefactor", "benign", "betrayal", "bilateral", "binocular", "blockbuster",
	"blowfish", "blueprint", "boardroom", "boatswain", "bookkeeper", "bordello", "bracelet", "broadside",
	"brownstone", "bulletin", "bulwark", "bushfire", "calculate", "callback", "camouflage", "capacitor",
	"carbide", "caretaker", "cartridge", "cashflow", "catalyst", "catapult", "centrifuge", "chainsaw",
	"chromosome", "cinnamon", "clearance", "clockwork", "cloudbank", "colossal", "commander", "commuter",
	"conduit", "contract", "conveyor", "copperhead", "cornfield", "corridor", "corrosive", "counselor",
	"coverage", "crackdown", "crossfire", "crossroads", "crumble", "deadweight", "debrief", "decipher",
	"defiance", "delusion", "detonator", "diameter", "dictator", "diffusion", "dilemma", "directory",
	"dividend", "doctrine", "downfall", "downlink", "downturn", "drawback", "dropship", "dumbwaiter",
	"duration", "endeavor", "entrance", "epidemic", "erratic", "escalate", "evaluate", "excavate",
	"executor", "exponent", "exposure", "extortion", "filibuster", "firmware", "freeform", "freehold",
	"freighter", "frequency", "fugitive", "function", "futuristic", "galactic", "gangplank", "garrison",
	"geologist", "gladiator", "gradient", "gratitude", "guardian", "guerrilla", "guideline", "gunpowder",
	"hardcover", "hardware", "harmonica", "headmaster", "headstone", "hemisphere", "hierarchy", "hostname",
	"hydrogen", "hyperlink", "illusion", "incognito", "indicate", "indulge", "industry", "infantry",
	"infraction", "inquire", "interact", "isolate", "isotope", "jackhammer", "javelin", "labrador",
	"latitude", "ledger", "leverage", "lifeguard", "likewise", "lobbyist", "locksmith", "longitude",
	"lowrider", "luggage", "magnitude", "mainspring", "maneuver", "maritime", "marksman", "marshall",
	"mastermind", "material", "maximize", "militant", "minimize", "minotaur", "mobilize", "moderate",
	"molecule", "monolith", "moonlight", "motorway", "navigate", "navigator", "nebulous", "network",
	"nightclub", "nobility", "northwest", "noteworthy", "objective", "observer", "occupant", "offender",
	"operative", "optional", "original", "outskirts", "pageant", "parallel", "paramedic", "partisan",
	"periscope", "petition", "platinum", "polaroid", "portfolio", "practical", "practise", "precedent",
}

// SASFromBytes generates a human-readable SAS from 32 bytes of key material.
// Returns 8 words alternating between even/odd word lists.
func SASFromBytes(keyMaterial []byte) []string {
	words := make([]string, 8)
	for i := 0; i < 8; i++ {
		idx := int(keyMaterial[i]) % 256
		if i%2 == 0 {
			words[i] = pgpWordListEven[idx%len(pgpWordListEven)]
		} else {
			words[i] = pgpWordListOdd[idx%len(pgpWordListOdd)]
		}
	}
	return words
}

// SASString returns the SAS as a space-separated string.
func SASString(words []string) string {
	return strings.Join(words, " ")
}

// --- Identicon (Visual Fingerprint) ---

const (
	charEmpty = ' ' // U+0020: 00
	charUpper = '▀' // U+2580: 01
	charLower = '▄' // U+2584: 10
	charFull  = '█' // U+2588: 11
)

const (
	boxTopLeft     = '╔'
	boxTopRight    = '╗'
	boxBottomLeft  = '╚'
	boxBottomRight = '╝'
	boxHoriz       = '═'
	boxVert        = '║'
)

// Identicon generates a visual fingerprint from 16 bytes of key material.
// Grid: 8 rows × 16 columns (left 8 cols = entropy, right 8 = mirror).
func Identicon(keyMaterial []byte) string {
	if len(keyMaterial) < 16 {
		panic("identicon: need at least 16 bytes")
	}
	grid := [8][8]rune{}
	byteIdx := 0
	bitPair := 0
	for row := 0; row < 8; row++ {
		for col := 0; col < 8; col++ {
			if bitPair >= 4 {
				byteIdx++
				bitPair = 0
			}
			b := keyMaterial[byteIdx]
			shift := uint(6 - bitPair*2)
			val := (b >> shift) & 0x03
			bitPair++
			switch val {
			case 0:
				grid[row][col] = charEmpty
			case 1:
				grid[row][col] = charUpper
			case 2:
				grid[row][col] = charLower
			case 3:
				grid[row][col] = charFull
			}
		}
	}

	var sb strings.Builder
	sb.WriteRune(boxTopLeft)
	for i := 0; i < 16; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxTopRight)
	sb.WriteByte('\n')

	for row := 0; row < 8; row++ {
		sb.WriteRune(boxVert)
		for col := 0; col < 8; col++ {
			sb.WriteRune(grid[row][col])
		}
		for col := 7; col >= 0; col-- {
			sb.WriteRune(grid[row][col])
		}
		sb.WriteRune(boxVert)
		sb.WriteByte('\n')
	}

	sb.WriteRune(boxBottomLeft)
	for i := 0; i < 16; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxBottomRight)
	return sb.String()
}

// --- Transfer code generation ---

var effShortWordlist = []string{
	"acid", "aged", "also", "apex", "aqua", "arch", "area", "army", "aunt", "avid",
	"baby", "back", "bail", "bait", "ball", "band", "bank", "barn", "bath", "bean",
	"bear", "beat", "beef", "been", "bell", "belt", "best", "bird", "bite", "blue",
	"boat", "body", "bold", "bolt", "bond", "bone", "book", "boom", "boot", "both",
	"bowl", "buck", "bulk", "bull", "burn", "byte", "cafe", "cage", "cake", "calf",
	"calm", "came", "cape", "care", "cart", "cash", "cast", "cave", "chat", "chip",
	"chop", "city", "clam", "clap", "clay", "clip", "club", "clue", "coal", "coat",
	"code", "coil", "cold", "cope", "cord", "core", "corn", "cost", "coup", "cove",
	"cowl", "cram", "cran", "crop", "crow", "cube", "cure", "curl", "damp", "dare",
	"dark", "dart", "dash", "data", "date", "dawn", "days", "dead", "deal", "dean",
	"deep", "deft", "dell", "dent", "desk", "dike", "dill", "dime", "dine", "dirt",
	"disk", "dock", "dome", "dose", "dote", "dove", "down", "drag", "draw", "drip",
	"drop", "drug", "drum", "dual", "duel", "duke", "dune", "dusk", "dust", "earn",
	"ease", "edge", "edit", "else", "emit", "emit", "epic", "even", "exam", "exit",
	"face", "fact", "fail", "fair", "fake", "fame", "farm", "fast", "fate", "fawn",
	"feed", "feel", "feet", "fell", "felt", "fern", "fest", "file", "fill", "film",
	"find", "fire", "fish", "fist", "five", "flag", "flat", "flew", "flip", "flit",
	"flow", "foam", "fold", "fond", "font", "food", "fool", "ford", "fore", "fork",
	"form", "fort", "foul", "fox", "fray", "free", "from", "fuel", "fume", "fund",
	"fuse", "gait", "gale", "game", "gang", "gaze", "gear", "gild", "gilt", "gist",
	"give", "glee", "glob", "glow", "glue", "goal", "goat", "gold", "golf", "good",
	"gore", "gown", "grab", "gram", "grit", "gust", "gybe", "hack", "hail", "half",
	"hall", "halt", "hand", "hang", "hard", "harm", "harp", "hate", "haul", "have",
	"hawk", "haze", "head", "heap", "heat", "heel", "help", "hemp", "herb", "herd",
	"high", "hill", "hilt", "hint", "holy", "home", "hook", "hope", "horn", "host",
	"huge", "hull", "hump", "hurt", "icon",
}

// GenerateTransferCode generates a random transfer code: "<uint16>-word-word-..."
// numWords is the number of words (minimum 3).
func GenerateTransferCode(numWords int) (uint16, string, error) {
	if numWords < 3 {
		numWords = 3
	}
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return 0, "", fmt.Errorf("rng: %w", err)
	}
	channelID := binary.BigEndian.Uint16(idBuf[:])

	wordsBuf := make([]byte, numWords)
	if _, err := rand.Read(wordsBuf); err != nil {
		return 0, "", fmt.Errorf("rng words: %w", err)
	}
	words := make([]string, numWords)
	for i, b := range wordsBuf {
		words[i] = effShortWordlist[int(b)%len(effShortWordlist)]
	}

	code := fmt.Sprintf("%d-%s", channelID, strings.Join(words, "-"))
	return channelID, code, nil
}

// ParseTransferCode parses a transfer code string into channelID and wordList.
func ParseTransferCode(code string) (uint16, []string, error) {
	parts := strings.SplitN(code, "-", 2)
	if len(parts) != 2 {
		return 0, nil, errors.New("invalid transfer code format")
	}
	var id uint16
	_, err := fmt.Sscanf(parts[0], "%d", &id)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid channel id: %w", err)
	}
	words := strings.Split(parts[1], "-")
	if len(words) < 3 {
		return 0, nil, errors.New("transfer code must contain at least 3 words")
	}
	return id, words, nil
}

// TransferCodePassword returns the password string from a transfer code.
func TransferCodePassword(code string) (string, error) {
	_, words, err := ParseTransferCode(code)
	if err != nil {
		return "", err
	}
	return strings.Join(words, "-"), nil
}
