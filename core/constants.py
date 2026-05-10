# core/constants.py
#
# All protocol constants in one place.
# Every other module imports from here.
#
# Do not change these values after generating
# vaults -- existing vaults will be incompatible
# with any changed values.
#
# ---------------------------------------------------------------------------
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Complete rewrite. See README.md, CHANGELOG.md, TECHNICAL_OVERVIEW.md.
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-08  M.Lines   v3.0:   APP_VERSION updated to 3.0
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DURESS PASSPHRASE
# ---------------------------------------------------------------------------
# If set to a non-empty string, entering this passphrase at any unlock
# prompt silently wipes all vault data and credentials and resets the
# app to factory state. The response is "Wrong passphrase." --
# indistinguishable from a normal failed entry.
#
# To enable: replace None with a string, e.g.:
#   DURESS_PASSPHRASE = "abandon ship"
#
# To disable: set to None (default).
#
# Rules:
#   - Must differ from your real passphrase
#   - Stored in plaintext in this file
#   - Do not reuse any passphrase used elsewhere
# ---------------------------------------------------------------------------
DURESS_PASSPHRASE = None

# ---------------------------------------------------------------------------
# Pad parameters
# ---------------------------------------------------------------------------

PAD_SIZE        = 1024    # bytes per pad -- fits ~170 words of text
PAD_COUNT       = 5000    # pads per vault
PAD_ASSIGN_SIZE = 2500    # pads assigned to each party

# ---------------------------------------------------------------------------
# Wire format
# Every message transmitted is exactly TRANSMISSION_SIZE bytes. Always.
# No exceptions. An observer cannot determine message length from size.
#
# Layout:
#   [BUNDLE_ID: 4 bytes plaintext] -- identifies which vault
#   [PAD_ID:    4 bytes plaintext] -- identifies which pad within vault
#   [PAYLOAD:   1024 bytes]        -- encrypted content
# ---------------------------------------------------------------------------

BUNDLE_ID_BYTES   = 4
PAD_ID_BYTES      = 4
HEADER_SIZE       = BUNDLE_ID_BYTES + PAD_ID_BYTES   # 8 bytes total

TRANSMISSION_SIZE = HEADER_SIZE + PAD_SIZE           # 1032 bytes total

# ---------------------------------------------------------------------------
# Encrypted payload internal layout
# The payload is exactly PAD_SIZE bytes after decryption.
#
# Layout:
#   [TYPE:        1 byte ]  -- message type
#   [SEQUENCE:    4 bytes]  -- per-contact send counter, starts at 1
#   [CHECKSUM:    8 bytes]  -- SHA256[:8] of content, tamper detection
#   [CONTENT_LEN: 2 bytes]  -- actual content length in bytes
#   [CONTENT:     variable] -- UTF-8 encoded message text
#   [PADDING:     random  ] -- random bytes filling remainder to PAD_SIZE
# ---------------------------------------------------------------------------

PAYLOAD_TYPE_OFFSET        = 0
PAYLOAD_SEQUENCE_OFFSET    = 1
PAYLOAD_CHECKSUM_OFFSET    = 5
PAYLOAD_CONTENT_LEN_OFFSET = 13
PAYLOAD_CONTENT_OFFSET     = 15

PAYLOAD_HEADER_SIZE = 15    # 1 + 4 + 8 + 2
MAX_CONTENT_BYTES   = PAD_SIZE - PAYLOAD_HEADER_SIZE   # 1009 bytes
                                                        # ~170 words

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

TYPE_POST    = 0x01   # a correspondence message
TYPE_REPLY   = 0x02   # a reply
TYPE_PADDING = 0x03   # dummy message -- discard silently

KNOWN_TYPES  = {TYPE_POST, TYPE_REPLY, TYPE_PADDING}

# ---------------------------------------------------------------------------
# Vault file format
#
# Layout on disk (all values encrypted except SALT):
#   [SALT:      32 bytes]  -- unencrypted, used to derive key
#   [ENCRYPTED BLOCK:]
#     [MAGIC:    8 bytes]  -- confirms correct passphrase on load
#     [CHECKSUM: 32 bytes] -- SHA256 of pad data, confirms integrity
#     [VERSION:  2 bytes]  -- vault format version
#     [PAD_COUNT:4 bytes]  -- number of pads (always PAD_COUNT)
#     [PAD_SIZE: 4 bytes]  -- bytes per pad (always PAD_SIZE)
#     [BUNDLE_ID: 4 bytes] -- vault bundle ID
#     [ASSIGN: 5000 bytes]  -- send pad assignment list
#     [INDEX:  625 bytes]  -- used/unused bitmap, 1 bit per pad
#     [FLAGS:   2 bytes]   -- feature flags (VAULT_FLAG_EPHEMERAL)
#     [PAD_DATA: ~5MB]    -- the actual pad bytes
#     [PAD_DATA: ~5MB]    -- the actual pad bytes
# ---------------------------------------------------------------------------

VAULT_MAGIC         = b'LBVAULT2'   # 8 bytes, confirms correct passphrase
VAULT_VERSION       = 3            # v3 adds SUBJECT_KEY field to header
SUBJECT_KEY_SIZE    = 32           # bytes for subject obfuscation HMAC key
VAULT_SALT_SIZE     = 32
VAULT_MAGIC_SIZE     = 8
VAULT_CHECKSUM_SIZE  = 32
VAULT_VERSION_SIZE   = 2
VAULT_COUNT_SIZE     = 4
VAULT_PADSIZE_SIZE   = 4
VAULT_BUNDLE_ID_SIZE = 4                         # bundle ID
VAULT_ASSIGN_SIZE    = PAD_ASSIGN_SIZE * 2        # assignment list:
                                                   # PAD_ASSIGN_SIZE uint16 values
                                                   # values = 10000 bytes
VAULT_INDEX_SIZE     = PAD_COUNT // 8             # 1250 bytes
VAULT_FLAGS_SIZE     = 2                          # uint16 feature flags
VAULT_PAD_DATA_SIZE  = PAD_COUNT * PAD_SIZE

# Vault flags (VAULT_FLAGS field, uint16 big-endian)
VAULT_FLAG_EPHEMERAL = 0x0001  # ephemeral mode: no history, pad zeroed after use

SUBJECT_TOKEN_BYTES  = 8               # bytes per token in lookup table
VAULT_TOKEN_TABLE_SIZE = PAD_COUNT * SUBJECT_TOKEN_BYTES  # 40,000 bytes

VAULT_HEADER_SIZE   = (VAULT_MAGIC_SIZE +
                       VAULT_CHECKSUM_SIZE +
                       VAULT_VERSION_SIZE +
                       VAULT_COUNT_SIZE +
                       VAULT_PADSIZE_SIZE +
                       VAULT_BUNDLE_ID_SIZE +
                       VAULT_ASSIGN_SIZE +
                       VAULT_INDEX_SIZE +
                       VAULT_FLAGS_SIZE +
                       SUBJECT_KEY_SIZE +
                       VAULT_TOKEN_TABLE_SIZE)  # v3: token lookup table

# ---------------------------------------------------------------------------
# Key derivation
# PBKDF2-HMAC-SHA256 with a high iteration count to slow brute force.
# ---------------------------------------------------------------------------

KDF_ITERATIONS          = 200000   # personal vault and credentials
KDF_TRANSFER_ITERATIONS = 2000000  # transfer vault -- one-time cost
KDF_KEY_SIZE            = 32       # 256-bit key

# ---------------------------------------------------------------------------
# Config file
# Stored unencrypted -- contains only the KDF salt and
# failed attempt tracking. No sensitive data.
# ---------------------------------------------------------------------------

APP_VERSION          = '3.3.0'

DISCLAIMER_TEXT = (
    "This project is an experimental proof of concept and is provided "
    "\"as is,\" without warranty of any kind. The software may contain "
    "latent bugs, design flaws, security vulnerabilities, or other "
    "defects that could result in unexpected behavior, data loss, "
    "security compromise, or system failure. By using this software, "
    "the user acknowledges that they have read and understood the "
    "limitations, assumptions, and threat considerations described in "
    "the documentation, including the README and threat model files, "
    "and accepts all risks associated with its use."
)


CONFIG_VERSION          = 1
CONFIG_SALT_SIZE        = VAULT_SALT_SIZE
MAX_PASSPHRASE_ATTEMPTS = 10

# ---------------------------------------------------------------------------
# FAILED ATTEMPT LOCKOUT DELAYS
# ---------------------------------------------------------------------------
# Minimum seconds to wait after a failed attempt before the next attempt
# is accepted. Keyed by attempt number (1-indexed). Attempts not listed
# have no enforced delay. Survives quit-and-restart via config.dat timestamp.
# ---------------------------------------------------------------------------
LOCKOUT_DELAYS = {
    6:  30,       # 30 seconds
    7:  60,       # 1 minute
    8:  300,      # 5 minutes
    9:  1800,     # 30 minutes
    10: None,     # wipe -- no delay, handled separately
}

# History display
HISTORY_PAGE_SIZE       = 5    # messages per page in history view

# ---------------------------------------------------------------------------
# Transfer vault
# A temporary vault file encrypted with a short-lived transfer passphrase
# for exchange between Alice and Bob.
# Same format as the personal vault but distinguished by magic bytes.
# ---------------------------------------------------------------------------

TRANSFER_MAGIC = b'LBTRANS2'   # distinguishes transfer from personal vault

# ---------------------------------------------------------------------------
# Wordlist for transfer passphrase generation
# Four words chosen randomly from this list.
# Words are short, common, and unambiguous when spoken aloud.
# ---------------------------------------------------------------------------

WORDLIST = [
    'able', 'acid', 'aged', 'also', 'area', 'army', 'away',
    'back', 'ball', 'band', 'bank', 'base', 'bath', 'bear',
    'beat', 'been', 'bell', 'best', 'bill', 'bird', 'blow',
    'blue', 'boat', 'body', 'bolt', 'bond', 'bone', 'book',
    'born', 'both', 'bowl', 'burn', 'bush', 'busy', 'cafe',
    'cage', 'cake', 'call', 'calm', 'came', 'camp', 'card',
    'care', 'cart', 'case', 'cash', 'cast', 'cave', 'cell',
    'chef', 'chip', 'city', 'clam', 'clan', 'clap', 'clay',
    'clip', 'club', 'clue', 'coal', 'coat', 'code', 'coil',
    'coin', 'cold', 'come', 'cook', 'cool', 'cope', 'copy',
    'core', 'corn', 'cost', 'coup', 'cove', 'crew', 'crop',
    'curb', 'cure', 'curl', 'cute', 'dark', 'data', 'date',
    'dawn', 'days', 'dead', 'deal', 'dear', 'debt', 'deck',
    'deed', 'deep', 'deer', 'deny', 'desk', 'dew',  'diet',
    'dirt', 'dish', 'disk', 'dive', 'dock', 'does', 'dome',
    'door', 'dose', 'dove', 'down', 'draw', 'drew', 'drop',
    'drum', 'dual', 'duck', 'dull', 'dune', 'dusk', 'dust',
    'duty', 'each', 'earl', 'earn', 'ease', 'east', 'easy',
    'edge', 'else', 'emit', 'epic', 'even', 'ever', 'evil',
    'exam', 'exit', 'expo', 'face', 'fact', 'fail', 'fair',
    'fall', 'fame', 'farm', 'fast', 'fate', 'fear', 'feat',
    'feed', 'feel', 'feet', 'fell', 'felt', 'fern', 'file',
    'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish',
    'fist', 'fits', 'flag', 'flat', 'flew', 'flip', 'flow',
    'foam', 'fold', 'folk', 'fond', 'font', 'food', 'fool',
    'ford', 'fore', 'fork', 'form', 'fort', 'foul', 'four',
    'free', 'from', 'fuel', 'full', 'fund', 'fuse', 'gain',
    'game', 'gate', 'gave', 'gaze', 'gear', 'gene', 'gift',
    'give', 'glad', 'glow', 'glue', 'goal', 'goes', 'gold',
    'golf', 'gone', 'good', 'grab', 'gray', 'grew', 'grid',
    'grip', 'grow', 'gulf', 'gust', 'hair', 'half', 'hall',
    'hand', 'hang', 'hard', 'harm', 'harp', 'have', 'hawk',
    'head', 'heal', 'heap', 'heat', 'heel', 'held', 'helm',
    'help', 'herb', 'herd', 'here', 'hero', 'hide', 'high',
    'hill', 'hint', 'hire', 'hold', 'hole', 'home', 'hook',
    'hope', 'horn', 'hose', 'host', 'hour', 'huge', 'hull',
    'hung', 'hunt', 'hurt', 'icon', 'idea', 'idle', 'inch',
    'into', 'iron', 'isle', 'item', 'jade', 'jail', 'jazz',
    'join', 'joke', 'jolt', 'jump', 'june', 'jury', 'just',
    'keen', 'keep', 'kelp', 'kept', 'kern', 'keys', 'kind',
    'king', 'knot', 'know', 'lack', 'lake', 'lamp', 'land',
    'lane', 'lark', 'last', 'late', 'lava', 'lawn', 'lead',
    'leaf', 'lean', 'leap', 'left', 'lend', 'lens', 'lest',
    'lift', 'like', 'lime', 'line', 'link', 'lion', 'list',
    'live', 'load', 'loan', 'lock', 'loft', 'long', 'look',
    'loom', 'loop', 'lore', 'lose', 'loss', 'lost', 'loud',
    'love', 'luck', 'lull', 'lump', 'lung', 'lure', 'mace',
    'made', 'mail', 'main', 'make', 'mall', 'malt', 'many',
    'mark', 'mars', 'mast', 'math', 'maze', 'meal', 'mean',
    'meet', 'melt', 'memo', 'menu', 'mesh', 'mild', 'mile',
    'milk', 'mill', 'mine', 'mint', 'miss', 'mist', 'mode',
    'mole', 'mood', 'moon', 'more', 'most', 'move', 'much',
    'mule', 'must', 'myth', 'nail', 'name', 'navy', 'near',
    'neck', 'need', 'nest', 'next', 'nice', 'nine', 'node',
    'none', 'noon', 'norm', 'nose', 'note', 'nova', 'null',
    'oath', 'obey', 'odds', 'once', 'only', 'open', 'oval',
    'oven', 'over', 'pace', 'pack', 'page', 'paid', 'pain',
    'pair', 'pale', 'palm', 'park', 'part', 'pass', 'past',
    'path', 'pave', 'peak', 'pear', 'peat', 'peel', 'peer',
    'pick', 'pier', 'pile', 'pine', 'pink', 'pipe', 'plan',
    'play', 'plot', 'plow', 'plug', 'plum', 'plus', 'poem',
    'poet', 'pole', 'poll', 'pond', 'pool', 'poor', 'pore',
    'port', 'pose', 'post', 'pour', 'prey', 'prop', 'pull',
    'pump', 'pure', 'push', 'quit', 'race', 'rack', 'rage',
    'raid', 'rail', 'rain', 'rake', 'ramp', 'rang', 'rank',
    'rare', 'rata', 'rate', 'read', 'real', 'reap', 'reed',
    'reef', 'reel', 'rely', 'rent', 'rest', 'rice', 'rich',
    'ride', 'ring', 'riot', 'rise', 'risk', 'road', 'roam',
    'roar', 'robe', 'rock', 'rode', 'role', 'roll', 'roof',
    'room', 'root', 'rope', 'rose', 'ruin', 'rule', 'rung',
    'rush', 'rust', 'safe', 'sage', 'sail', 'sake', 'salt',
    'same', 'sand', 'sane', 'sang', 'save', 'scan', 'seal',
    'seam', 'seat', 'seed', 'seek', 'seem', 'seen', 'self',
    'sell', 'send', 'sent', 'shed', 'ship', 'shoe', 'shop',
    'show', 'shut', 'sick', 'side', 'sigh', 'sign', 'silk',
    'silo', 'sing', 'sink', 'site', 'size', 'skin', 'skip',
    'slab', 'slam', 'slap', 'slim', 'slip', 'slow', 'slug',
    'snap', 'snow', 'soak', 'soar', 'sock', 'soft', 'soil',
    'sold', 'sole', 'some', 'song', 'soon', 'sort', 'soul',
    'soup', 'span', 'spin', 'spot', 'spur', 'star', 'stay',
    'stem', 'step', 'stew', 'stir', 'stop', 'stub', 'such',
    'suit', 'sung', 'sunk', 'sure', 'surf', 'swan', 'swap',
    'sway', 'swim', 'tail', 'tale', 'tall', 'tang', 'tank',
    'tape', 'task', 'team', 'tear', 'tell', 'tend', 'tent',
    'term', 'test', 'text', 'than', 'that', 'them', 'then',
    'they', 'thin', 'this', 'tide', 'tier', 'till', 'tilt',
    'time', 'tiny', 'tire', 'toad', 'toil', 'told', 'toll',
    'tomb', 'tone', 'tool', 'tops', 'tore', 'torn', 'toss',
    'tour', 'town', 'trap', 'tray', 'trek', 'trim', 'trio',
    'trip', 'trod', 'true', 'tube', 'tuck', 'tuna', 'tune',
    'turf', 'turn', 'tusk', 'twin', 'type', 'upon', 'used',
    'vale', 'vary', 'vast', 'veil', 'vein', 'very', 'view',
    'vine', 'void', 'volt', 'vote', 'wade', 'wage', 'wake',
    'walk', 'wall', 'wand', 'warm', 'wary', 'wave', 'weak',
    'weal', 'weed', 'well', 'went', 'were', 'west', 'what',
    'when', 'whom', 'wide', 'wild', 'will', 'wind', 'wine',
    'wing', 'wire', 'wise', 'wish', 'with', 'woke', 'wolf',
    'wood', 'wool', 'word', 'wore', 'work', 'worm', 'worn',
    'wrap', 'wren', 'yard', 'yarn', 'year', 'your', 'zeal',
    'zero', 'zinc', 'zone',
]

# Confirm wordlist has enough words for adequate entropy.
# 6 words from this list. Checked at import time.
assert len(WORDLIST) >= 256, (
    f"Wordlist too small: {len(WORDLIST)} words. "
    "Need at least 256 for adequate transfer passphrase entropy."
)

# ---------------------------------------------------------------------------
# Platform detection
# Used to set the data directory path.
# 2026-05-09  M.Lines   v3.1.0: APP_VERSION updated to 3.1.0; v3.1.0 baseline release
# ---------------------------------------------------------------------------

def is_pythonista() -> bool:
    """
    Returns True if running inside Pythonista on iPad.
    Returns False if running on Mac or any other platform.

    Detection method: Pythonista includes a 'console' module
    that does not exist in standard Python.
    """
    try:
        import console   # Pythonista-specific module
        return True
    except ImportError:
        return False
