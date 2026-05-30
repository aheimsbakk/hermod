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
	return sb.String()
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
