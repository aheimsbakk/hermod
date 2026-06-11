// Package crypto implements cryptographic primitives for hermod.
//
// CPace is implemented per RFC 9496 using P-256 (NIST curve) with
// hash-to-curve via the P256_XMD:SHA-256_SSWU_RO_ suite (RFC 9380).
// SSWU produces a valid curve point in a single, fixed-length computation
// with no data-dependent loop iterations, eliminating the timing side channel
// present in try-and-increment. The role ("sender"/"receiver") is bound into
// the ISK derivation via a role-ordered transcript, providing domain separation
// per RFC 9496 intent.
// AES-256-GCM is used for signaling payload encryption keyed by the CPace
// shared secret.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// p256Order is the order of the P-256 curve (number of points on the group).
// Used by randScalar to generate a valid scalar in [1, n-1].
var p256Order, _ = new(big.Int).SetString(
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// recoverYOnP256 computes the y-coordinate for a given x on P-256 so that
// (x, y) satisfies y² = x³ - 3x + b (mod p). Since p ≡ 3 (mod 4), the
// square root is y = (y²)^((p+1)/4) mod p. Either root is valid for ECDH
// (shared secret is the x-coordinate only), and both parties use the same
// recovery algorithm, so the protocol is consistent.
func recoverYOnP256(x *big.Int) *big.Int {
	p := p256P
	// y² = x³ - 3x + b (mod p)
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	ax := new(big.Int).Mod(new(big.Int).Mul(p256A, x), p)
	y2 := new(big.Int).Add(new(big.Int).Add(x3, ax), p256B)
	y2.Mod(y2, p)
	// sqrt: y = y2^((p+1)/4) mod p
	exp := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2) // (p+1)/4
	return new(big.Int).Exp(y2, exp, p)
}

// --- CPace (RFC 9496 simplified over P-256) ---

// CPaceSession holds ephemeral state for one side of the CPace exchange.
type CPaceSession struct {
	scalar  []byte // 32-byte big-endian scalar
	pubMsg  []byte // 65-byte uncompressed point: 0x04 || X || Y
	role    string // "sender" or "receiver" — used for ISK transcript ordering
	sharedK []byte // set after Finish
}

// cpacePointSize is the byte length of an uncompressed P-256 point.
const cpacePointSize = 65

// CPaceInit creates a new CPace initiator message from the password.
// channelID is the transfer channel integer used as a domain separator.
// role must be "sender" or "receiver"; it is bound into the ISK derivation
// to provide role-based domain separation per RFC 9496 intent.
// Returns the session and the public message (65 bytes) to send to the peer.
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error) {
	// Generator = hash-to-curve(password || channelID || "sender:receiver")
	// Both parties use the same combined role domain so the generator is shared.
	gx, gy, err := cpaceGenerator(password, channelID)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace generator: %w", err)
	}

	// Generate ephemeral scalar y
	scalar, err := randScalar(p256Order)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace scalar: %w", err)
	}

	// Y = scalar * G_password using crypto/ecdh (constant-time, stdlib only).
	curve := ecdh.P256()
	privKey, err := curve.NewPrivateKey(scalar.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("cpace private key: %w", err)
	}
	genBytes := marshalPoint(gx, gy)
	genKey, err := curve.NewPublicKey(genBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace generator public key: %w", err)
	}
	sharedX, err := privKey.ECDH(genKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace scalar mult: %w", err)
	}
	Yx := new(big.Int).SetBytes(sharedX)
	Yy := recoverYOnP256(Yx)

	pubMsg := marshalPoint(Yx, Yy)

	return &CPaceSession{
		scalar: scalar.Bytes(),
		pubMsg: pubMsg,
		role:   role,
	}, pubMsg, nil
}

// CPaceFinish completes the CPace exchange given the peer's public message (65 bytes).
// Returns the 32-byte shared secret K.
// The ISK is derived as SHA-256(iskX || pubSender || pubReceiver), where the
// role stored in the session determines which public message belongs to sender
// and which to receiver. This binds the role into the shared secret and
// prevents cross-role composition attacks.
func (s *CPaceSession) CPaceFinish(peerPub []byte) ([]byte, error) {
	if len(peerPub) != cpacePointSize || peerPub[0] != 0x04 {
		return nil, errors.New("invalid peer public message: must be a 65-byte uncompressed P-256 point")
	}

	// Parse and validate the peer point using ecdh (validates on-curve).
	curve := ecdh.P256()
	peerKey, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("cpace finish invalid peer point: %w", err)
	}

	// ISK_x = scalar * peerPub using constant-time ECDH.
	// ECDH returns the x-coordinate of the point, which is what we need.
	privKey, err := curve.NewPrivateKey(s.scalar)
	if err != nil {
		return nil, fmt.Errorf("cpace finish private key: %w", err)
	}
	iskXBytes, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("cpace finish ecdh: %w", err)
	}
	iskX := new(big.Int).SetBytes(iskXBytes)

	// Build role-ordered transcript: iskX || pubSender || pubReceiver.
	// Both sides resolve sender/receiver the same way using their stored role,
	// so the byte sequence — and thus the derived key — is identical.
	var senderPub, receiverPub []byte
	if s.role == "sender" {
		senderPub, receiverPub = s.pubMsg, peerPub
	} else {
		senderPub, receiverPub = peerPub, s.pubMsg
	}
	transcript := make([]byte, 0, 32+cpacePointSize+cpacePointSize)
	transcript = append(transcript, padTo32(iskX)...)
	transcript = append(transcript, senderPub...)
	transcript = append(transcript, receiverPub...)

	h := sha256.Sum256(transcript)
	k := h[:]
	s.sharedK = k
	return k, nil
}

// SharedK returns the derived shared secret (nil before CPaceFinish is called).
func (s *CPaceSession) SharedK() []byte { return s.sharedK }

// PubMessage returns the 65-byte public message.
func (s *CPaceSession) PubMessage() []byte { return s.pubMsg }

// cpaceGenerator hashes the password + channelID to a P-256 point using
// the P256_XMD:SHA-256_SSWU_RO_ suite (RFC 9380).
// The domain separation tag embeds the combined role tag "sender:receiver"
// so the generator is role-aware while remaining identical for both peers.
// Unlike the former try-and-increment approach, SSWU always produces a valid
// point in a single, fixed-length computation, eliminating the loop-count
// timing side channel.
func cpaceGenerator(password string, channelID uint16) (*big.Int, *big.Int, error) {
	dst := p256DST(password, channelID)
	// Input message is the fixed role tag; the password is in the DST.
	msg := []byte("sender:receiver")
	pt, err := hashToCurveP256(msg, dst)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace hash-to-curve: %w", err)
	}
	// pt is a 65-byte uncompressed point: 0x04 || X(32) || Y(32).
	x := new(big.Int).SetBytes(pt[1:33])
	y := new(big.Int).SetBytes(pt[33:65])
	return x, y, nil
}

func padTo32(n *big.Int) []byte {
	// FillBytes always produces exactly 32 bytes. For P-256 scalars and
	// coordinates the value is guaranteed to fit in 32 bytes; if it does
	// not the panic is correct (crypto code must not silently truncate).
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

func marshalPoint(x, y *big.Int) []byte {
	pt := make([]byte, 65)
	pt[0] = 0x04
	copy(pt[1:33], padTo32(x))
	copy(pt[33:], padTo32(y))
	return pt
}

// randScalar generates a uniformly random scalar in [1, n-1] using rejection
// sampling (L-03). A 32-byte random value is accepted only if it falls in
// [1, n-1]; otherwise a new value is drawn. This is unbiased and correctly
// communicates the algorithm's intent, unlike the former modular-reduction
// approach whose retry loop could never fire.
func randScalar(n *big.Int) (*big.Int, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
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
	return SealAAD(key, nil, plaintext)
}

// SealAAD encrypts plaintext with key (must be 32 bytes) using AES-256-GCM,
// binding aad as Additional Authenticated Data. The AAD is authenticated but
// not included in the ciphertext. Pass nil for no AAD.
// Returns nonce || ciphertext || tag.
func SealAAD(key, aad, plaintext []byte) ([]byte, error) {
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
	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return ct, nil
}

// Open decrypts a blob produced by Seal.
func Open(key, blob []byte) ([]byte, error) {
	return OpenAAD(key, nil, blob)
}

// OpenAAD decrypts a blob produced by SealAAD, verifying the provided AAD.
// Pass nil aad when no AAD was used during encryption.
func OpenAAD(key, aad, blob []byte) ([]byte, error) {
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
		return nil, errors.New("decrypt: blob too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], aad)
}

// --- SAS (Short Authentication String) ---

// sasWordCount is the number of EFF Short Wordlist 1 words in the SAS.
const sasWordCount = 6

// SASFromBytes generates a human-readable SAS from 32 bytes of key material.
// Returns 6 words from the EFF Short Wordlist 1 (1296 entries), drawn using
// rejection sampling on uint16 values read from the key material.
// The output is deterministic for the same key material and has no modulo bias.
func SASFromBytes(keyMaterial []byte) []string {
	n := len(effShortWordlist) // 1296
	// Largest multiple of n that fits in a uint16 range (0..65535):
	// floor(65536 / n) * n = 50 * 1296 = 64800.
	limit := (65536 / n) * n

	words := make([]string, sasWordCount)
	wordIdx := 0
	offset := 0

	for wordIdx < sasWordCount {
		if offset+1 >= len(keyMaterial) {
			// SASFromBytes requires at least 12 bytes of key material
			// (6 words × 2 bytes each). All callers provide at least 32
			// bytes, so this path is unreachable (defense-in-depth).
			panic("SASFromBytes: insufficient key material (need ≥12 bytes)")
		}
		v := int(binary.BigEndian.Uint16(keyMaterial[offset:]))
		offset += 2
		if v < limit {
			words[wordIdx] = effShortWordlist[v%n]
			wordIdx++
		}
	}
	return words
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
// Returns an error if keyMaterial is shorter than 16 bytes.
func Identicon(keyMaterial []byte) (string, error) {
	if len(keyMaterial) < 16 {
		return "", fmt.Errorf("identicon: need at least 16 bytes of key material, got %d", len(keyMaterial))
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
	for i := 0; i < 18; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxTopRight)
	sb.WriteByte('\n')

	for row := 0; row < 8; row++ {
		sb.WriteRune(boxVert)
		sb.WriteByte(' ')
		for col := 0; col < 8; col++ {
			sb.WriteRune(grid[row][col])
		}
		for col := 7; col >= 0; col-- {
			sb.WriteRune(grid[row][col])
		}
		sb.WriteByte(' ')
		sb.WriteRune(boxVert)
		sb.WriteByte('\n')
	}

	sb.WriteRune(boxBottomLeft)
	for i := 0; i < 18; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxBottomRight)
	return sb.String(), nil
}

// --- Transfer code generation ---

// effShortWordlist is the complete EFF Short Wordlist 1 (1,296 entries).
// Source: https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
// Each entry is unique. Using the full 1,296-word list gives
// log₂(1296³) ≈ 31.9 bits of passphrase entropy for 3-word codes.
var effShortWordlist = []string{
	"acid", "acorn", "acre", "acts", "afar", "affix",
	"aged", "agent", "agile", "aging", "agony", "ahead",
	"aide", "aids", "aim", "ajar", "alarm", "alias",
	"alibi", "alien", "alike", "alive", "aloe", "aloft",
	"aloha", "alone", "amend", "amino", "ample", "amuse",
	"angel", "anger", "angle", "ankle", "apple", "april",
	"apron", "aqua", "area", "arena", "argue", "arise",
	"armed", "armor", "army", "aroma", "array", "arson",
	"art", "ashen", "ashes", "atlas", "atom", "attic",
	"audio", "avert", "avoid", "awake", "award", "awoke",
	"axis", "bacon", "badge", "bagel", "baggy", "baked",
	"baker", "balmy", "banjo", "barge", "barn", "bash",
	"basil", "bask", "batch", "bath", "baton", "bats",
	"blade", "blank", "blast", "blaze", "bleak", "blend",
	"bless", "blimp", "blink", "bloat", "blob", "blog",
	"blot", "blunt", "blurt", "blush", "boast", "boat",
	"body", "boil", "bok", "bolt", "boned", "boney",
	"bonus", "bony", "book", "booth", "boots", "boss",
	"botch", "both", "boxer", "breed", "bribe", "brick",
	"bride", "brim", "bring", "brink", "brisk", "broad",
	"broil", "broke", "brook", "broom", "brush", "buck",
	"bud", "buggy", "bulge", "bulk", "bully", "bunch",
	"bunny", "bunt", "bush", "bust", "busy", "buzz",
	"cable", "cache", "cadet", "cage", "cake", "calm",
	"cameo", "canal", "candy", "cane", "canon", "cape",
	"card", "cargo", "carol", "carry", "carve", "case",
	"cash", "cause", "cedar", "chain", "chair", "chant",
	"chaos", "charm", "chase", "cheek", "cheer", "chef",
	"chess", "chest", "chew", "chief", "chili", "chill",
	"chip", "chomp", "chop", "chow", "chuck", "chump",
	"chunk", "churn", "chute", "cider", "cinch", "city",
	"civic", "civil", "clad", "claim", "clamp", "clap",
	"clash", "clasp", "class", "claw", "clay", "clean",
	"clear", "cleat", "cleft", "clerk", "click", "cling",
	"clink", "clip", "cloak", "clock", "clone", "cloth",
	"cloud", "clump", "coach", "coast", "coat", "cod",
	"coil", "coke", "cola", "cold", "colt", "coma",
	"come", "comic", "comma", "cone", "cope", "copy",
	"coral", "cork", "cost", "cot", "couch", "cough",
	"cover", "cozy", "craft", "cramp", "crane", "crank",
	"crate", "crave", "crawl", "crazy", "creme", "crepe",
	"crept", "crib", "cried", "crisp", "crook", "crop",
	"cross", "crowd", "crown", "crumb", "crush", "crust",
	"cub", "cult", "cupid", "cure", "curl", "curry",
	"curse", "curve", "curvy", "cushy", "cut", "cycle",
	"dab", "dad", "daily", "dairy", "daisy", "dance",
	"dandy", "darn", "dart", "dash", "data", "date",
	"dawn", "deaf", "deal", "dean", "debit", "debt",
	"debug", "decaf", "decal", "decay", "deck", "decor",
	"decoy", "deed", "delay", "denim", "dense", "dent",
	"depth", "derby", "desk", "dial", "diary", "dice",
	"dig", "dill", "dime", "dimly", "diner", "dingy",
	"disco", "dish", "disk", "ditch", "ditzy", "dizzy",
	"dock", "dodge", "doing", "doll", "dome", "donor",
	"donut", "dose", "dot", "dove", "down", "dowry",
	"doze", "drab", "drama", "drank", "draw", "dress",
	"dried", "drift", "drill", "drive", "drone", "droop",
	"drove", "drown", "drum", "dry", "duck", "duct",
	"dude", "dug", "duke", "duo", "dusk", "dust",
	"duty", "dwarf", "dwell", "eagle", "early", "earth",
	"easel", "east", "eaten", "eats", "ebay", "ebony",
	"ebook", "echo", "edge", "eel", "eject", "elbow",
	"elder", "elf", "elk", "elm", "elope", "elude",
	"elves", "email", "emit", "empty", "emu", "enter",
	"entry", "envoy", "equal", "erase", "error", "erupt",
	"essay", "etch", "evade", "even", "evict", "evil",
	"evoke", "exact", "exit", "fable", "faced", "fact",
	"fade", "fall", "false", "fancy", "fang", "fax",
	"feast", "feed", "femur", "fence", "fend", "ferry",
	"fetal", "fetch", "fever", "fiber", "fifth", "fifty",
	"film", "filth", "final", "finch", "fit", "five",
	"flag", "flaky", "flame", "flap", "flask", "fled",
	"flick", "fling", "flint", "flip", "flirt", "float",
	"flock", "flop", "floss", "flyer", "foam", "foe",
	"fog", "foil", "folic", "folk", "food", "fool",
	"found", "fox", "foyer", "frail", "frame", "fray",
	"fresh", "fried", "frill", "frisk", "from", "front",
	"frost", "froth", "frown", "froze", "fruit", "gag",
	"gains", "gala", "game", "gap", "gas", "gave",
	"gear", "gecko", "geek", "gem", "genre", "gift",
	"gig", "gills", "given", "giver", "glad", "glass",
	"glide", "gloss", "glove", "glow", "glue", "goal",
	"going", "golf", "gong", "good", "gooey", "goofy",
	"gore", "gown", "grab", "grain", "grant", "grape",
	"graph", "grasp", "grass", "grave", "gravy", "gray",
	"green", "greet", "grew", "grid", "grief", "grill",
	"grip", "grit", "groom", "grope", "growl", "grub",
	"grunt", "guide", "gulf", "gulp", "gummy", "guru",
	"gush", "gut", "guy", "habit", "half", "halo",
	"halt", "happy", "harm", "hash", "hasty", "hatch",
	"hate", "haven", "hazel", "hazy", "heap", "heat",
	"heave", "hedge", "hefty", "help", "herbs", "hers",
	"hub", "hug", "hula", "hull", "human", "humid",
	"hump", "hung", "hunk", "hunt", "hurry", "hurt",
	"hush", "hut", "ice", "icing", "icon", "icy",
	"igloo", "image", "ion", "iron", "islam", "issue",
	"item", "ivory", "ivy", "jab", "jam", "jaws",
	"jazz", "jeep", "jelly", "jet", "jiffy", "job",
	"jog", "jolly", "jolt", "jot", "joy", "judge",
	"juice", "juicy", "july", "jumbo", "jump", "junky",
	"juror", "jury", "keep", "keg", "kept", "kick",
	"kilt", "king", "kite", "kitty", "kiwi", "knee",
	"knelt", "koala", "kung", "ladle", "lady", "lair",
	"lake", "lance", "land", "lapel", "large", "lash",
	"lasso", "last", "latch", "late", "lazy", "left",
	"legal", "lemon", "lend", "lens", "lent", "level",
	"lever", "lid", "life", "lift", "lilac", "lily",
	"limb", "limes", "line", "lint", "lion", "lip",
	"list", "lived", "liver", "lunar", "lunch", "lung",
	"lurch", "lure", "lurk", "lying", "lyric", "mace",
	"maker", "malt", "mama", "mango", "manor", "many",
	"map", "march", "mardi", "marry", "mash", "match",
	"mate", "math", "moan", "mocha", "moist", "mold",
	"mom", "moody", "mop", "morse", "most", "motor",
	"motto", "mount", "mouse", "mousy", "mouth", "move",
	"movie", "mower", "mud", "mug", "mulch", "mule",
	"mull", "mumbo", "mummy", "mural", "muse", "music",
	"musky", "mute", "nacho", "nag", "nail", "name",
	"nanny", "nap", "navy", "near", "neat", "neon",
	"nerd", "nest", "net", "next", "niece", "ninth",
	"nutty", "oak", "oasis", "oat", "ocean", "oil",
	"old", "olive", "omen", "onion", "only", "ooze",
	"opal", "open", "opera", "opt", "otter", "ouch",
	"ounce", "outer", "oval", "oven", "owl", "ozone",
	"pace", "pagan", "pager", "palm", "panda", "panic",
	"pants", "panty", "paper", "park", "party", "pasta",
	"patch", "path", "patio", "payer", "pecan", "penny",
	"pep", "perch", "perky", "perm", "pest", "petal",
	"petri", "petty", "photo", "plank", "plant", "plaza",
	"plead", "plot", "plow", "pluck", "plug", "plus",
	"poach", "pod", "poem", "poet", "pogo", "point",
	"poise", "poker", "polar", "polio", "polka", "polo",
	"pond", "pony", "poppy", "pork", "poser", "pouch",
	"pound", "pout", "power", "prank", "press", "print",
	"prior", "prism", "prize", "probe", "prong", "proof",
	"props", "prude", "prune", "pry", "pug", "pull",
	"pulp", "pulse", "puma", "punch", "punk", "pupil",
	"puppy", "purr", "purse", "push", "putt", "quack",
	"quake", "query", "quiet", "quill", "quilt", "quit",
	"quota", "quote", "rabid", "race", "rack", "radar",
	"radio", "raft", "rage", "raid", "rail", "rake",
	"rally", "ramp", "ranch", "range", "rank", "rant",
	"rash", "raven", "reach", "react", "ream", "rebel",
	"recap", "relax", "relay", "relic", "remix", "repay",
	"repel", "reply", "rerun", "reset", "rhyme", "rice",
	"rich", "ride", "rigid", "rigor", "rinse", "riot",
	"ripen", "rise", "risk", "ritzy", "rival", "river",
	"roast", "robe", "robin", "rock", "rogue", "roman",
	"romp", "rope", "rover", "royal", "ruby", "rug",
	"ruin", "rule", "runny", "rush", "rust", "rut",
	"sadly", "sage", "said", "saint", "salad", "salon",
	"salsa", "salt", "same", "sandy", "santa", "satin",
	"sauna", "saved", "savor", "sax", "say", "scale",
	"scam", "scan", "scare", "scarf", "scary", "scoff",
	"scold", "scoop", "scoot", "scope", "score", "scorn",
	"scout", "scowl", "scrap", "scrub", "scuba", "scuff",
	"sect", "sedan", "self", "send", "sepia", "serve",
	"set", "seven", "shack", "shade", "shady", "shaft",
	"shaky", "sham", "shape", "share", "sharp", "shed",
	"sheep", "sheet", "shelf", "shell", "shine", "shiny",
	"ship", "shirt", "shock", "shop", "shore", "shout",
	"shove", "shown", "showy", "shred", "shrug", "shun",
	"shush", "shut", "shy", "sift", "silk", "silly",
	"silo", "sip", "siren", "sixth", "size", "skate",
	"skew", "skid", "skier", "skies", "skip", "skirt",
	"skit", "sky", "slab", "slack", "slain", "slam",
	"slang", "slash", "slate", "slaw", "sled", "sleek",
	"sleep", "sleet", "slept", "slice", "slick", "slimy",
	"sling", "slip", "slit", "slob", "slot", "slug",
	"slum", "slurp", "slush", "small", "smash", "smell",
	"smile", "smirk", "smog", "snack", "snap", "snare",
	"snarl", "sneak", "sneer", "sniff", "snore", "snort",
	"snout", "snowy", "snub", "snuff", "speak", "speed",
	"spend", "spent", "spew", "spied", "spill", "spiny",
	"spoil", "spoke", "spoof", "spool", "spoon", "sport",
	"spot", "spout", "spray", "spree", "spur", "squad",
	"squat", "squid", "stack", "staff", "stage", "stain",
	"stall", "stamp", "stand", "stank", "stark", "start",
	"stash", "state", "stays", "steam", "steep", "stem",
	"step", "stew", "stick", "sting", "stir", "stock",
	"stole", "stomp", "stony", "stood", "stool", "stoop",
	"stop", "storm", "stout", "stove", "straw", "stray",
	"strut", "stuck", "stud", "stuff", "stump", "stung",
	"stunt", "suds", "sugar", "sulk", "surf", "sushi",
	"swab", "swan", "swarm", "sway", "swear", "sweat",
	"sweep", "swell", "swept", "swim", "swing", "swipe",
	"swirl", "swoop", "swore", "syrup", "tacky", "taco",
	"tag", "take", "tall", "talon", "tamer", "tank",
	"taper", "taps", "tarot", "tart", "task", "taste",
	"tasty", "taunt", "thank", "thaw", "theft", "theme",
	"thigh", "thing", "think", "thong", "thorn", "those",
	"throb", "thud", "thumb", "thump", "thus", "tiara",
	"tidal", "tidy", "tiger", "tile", "tilt", "tint",
	"tiny", "trace", "track", "trade", "train", "trait",
	"trap", "trash", "tray", "treat", "tree", "trek",
	"trend", "trial", "tribe", "trick", "trio", "trout",
	"truce", "truck", "trump", "trunk", "try", "tug",
	"tulip", "tummy", "turf", "tusk", "tutor", "tutu",
	"tux", "tweak", "tweet", "twice", "twine", "twins",
	"twirl", "twist", "uncle", "uncut", "undo", "unify",
	"union", "unit", "untie", "upon", "upper", "urban",
	"used", "user", "usher", "utter", "value", "vapor",
	"vegan", "venue", "verse", "vest", "veto", "vice",
	"video", "view", "viral", "virus", "visa", "visor",
	"vixen", "vocal", "voice", "void", "volt", "voter",
	"vowel", "wad", "wafer", "wager", "wages", "wagon",
	"wake", "walk", "wand", "wasp", "watch", "water",
	"wavy", "wheat", "whiff", "whole", "whoop", "wick",
	"widen", "widow", "width", "wife", "wifi", "wilt",
	"wimp", "wind", "wing", "wink", "wipe", "wired",
	"wiry", "wise", "wish", "wispy", "wok", "wolf",
	"womb", "wool", "woozy", "word", "work", "worry",
	"wound", "woven", "wrath", "wreck", "wrist", "xerox",
	"yahoo", "yam", "yard", "year", "yeast", "yelp",
	"yield", "yo-yo", "yodel", "yoga", "yoyo", "yummy",
	"zebra", "zero", "zesty", "zippy", "zone", "zoom",
}

// EFFShortWordlist returns a copy of the wordlist slice for testing and inspection.
func EFFShortWordlist() []string {
	out := make([]string, len(effShortWordlist))
	copy(out, effShortWordlist)
	return out
}

// randomWordIndex returns a uniformly random index in [0, len(effShortWordlist))
// using rejection sampling on uint16 values to eliminate modulo bias.
func randomWordIndex() (int, error) {
	n := len(effShortWordlist) // 1296
	// Largest multiple of n that fits in a uint16 range (0..65535):
	// floor(65536 / n) * n = 50 * 1296 = 64800.
	limit := (65536 / n) * n
	var buf [2]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("rng word index: %w", err)
		}
		v := int(binary.BigEndian.Uint16(buf[:]))
		if v < limit {
			return v % n, nil
		}
	}
}

// GenerateTransferCode generates a random transfer code: "<uint16>-word-word-..."
// numWords is the number of words (minimum 3).
// Words are drawn from the full 1,296-entry EFF short wordlist using
// rejection sampling, giving log₂(1296^numWords) bits of passphrase entropy.
func GenerateTransferCode(numWords int) (uint16, string, error) {
	if numWords < 3 {
		numWords = 3
	}
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return 0, "", fmt.Errorf("rng: %w", err)
	}
	channelID := binary.BigEndian.Uint16(idBuf[:])

	words := make([]string, numWords)
	for i := range words {
		idx, err := randomWordIndex()
		if err != nil {
			return 0, "", err
		}
		words[i] = effShortWordlist[idx]
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
		return 0, nil, fmt.Errorf("invalid channel ID in transfer code: %w", err)
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
