#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
oracle_forms_burp.py  –  Burp Suite Extension (Jython / Python 2.7)

Oracle Forms FHT (HTTP Transport) Protocol Decoder.
Decrypts RC4-encrypted Oracle Forms traffic and displays decoded
messages in a dedicated tab in Burp's Proxy History / Repeater.

SETUP:
  Extender > Extensions > Add > Extension Type: Python
  Select this file. Burp will ask for Jython JAR if not set.

USAGE:
  1. Ensure Burp proxy is running BEFORE opening Oracle Forms.
  2. Start Oracle Forms – extension catches Pragma 1 (key derivation)
     then decodes everything from Pragma 3 onward automatically.
  3. Click any lservlet POST in Proxy History → "Oracle Forms" tab.
"""

from burp import IBurpExtender, IProxyListener, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.swing import JScrollPane, JTextArea, JPanel, JLabel, JButton, BorderFactory
from javax.swing import BoxLayout, SwingUtilities, JSplitPane, JPopupMenu, JMenuItem
from java.awt import BorderLayout, Font, Color, Dimension
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable
import threading
import struct
import re
import io

EXTENSION_NAME = "Oracle Forms Decoder"

# ── Property ID map (from ID.class, IDs 101-570) ─────────────────────────────

ID_MAP = {
    16:"TAG", 101:"APPLICATION", 102:"FORM_MODULE", 103:"NAME",
    104:"PARENT", 105:"CANCEL", 106:"CANCEL_LABEL", 107:"CANCEL_MNEMONIC",
    108:"COLTITLE", 109:"COLWIDTH", 110:"CONNECT_LABEL",
    111:"CONNECT_MNEMONIC", 112:"FIND_LABEL", 113:"FIND_MNEMONIC",
    114:"ICON_FILENAME", 115:"ALIGNMENT", 116:"LABEL",
    117:"MAX_LENGTH", 118:"NO_LABEL", 119:"OK_LABEL",
    120:"OK_MNEMONIC", 121:"RANGE", 122:"ROWVAL", 123:"SCROLL",
    124:"SEARCH_LABEL", 125:"SEARCH_MNEMONIC", 126:"SIZE",
    127:"STATUS", 128:"STYLE", 129:"TITLE", 130:"CANVASTYPE",
    131:"VALUE", 132:"WINDOW", 133:"CLEARDAMAGE", 134:"UI_PARENT",
    135:"LOCATION", 136:"INNERSIZE", 137:"OUTERSIZE",
    138:"CANVASMOVABLE", 139:"CANVASORIGIN", 140:"MNEMONIC",
    141:"NAVIGABLE", 142:"TABSTOP", 143:"GROUP", 144:"ENABLED",
    145:"EVENTMODE", 146:"FOREGROUND", 147:"BACKGROUND",
    148:"BGPATTERN", 149:"FONT", 150:"BORDERUSE", 151:"BORDERWD",
    152:"BORDER_BEVEL", 153:"BOUNDS", 154:"BORDER",
    155:"VISIBLERECT", 156:"ISMAPPED", 157:"ISVISIBLE",
    158:"USAGE", 159:"BASELINE", 160:"PRIVATE",
    161:"HIGHLIGHTFOCUS", 162:"BMUNPROTECTED", 163:"EVENTMASK",
    164:"MAPREQUEST", 165:"LANGUAGE_DIRECTION", 166:"DIRCHANGE",
    167:"VALIDKEYS", 168:"DEFAULTKEYS", 169:"DRAWTHRU",
    170:"CANVASHANDLE", 171:"DLGOK", 172:"MESSAGE", 173:"VISIBLE",
    174:"FOCUS", 175:"KEY", 176:"SKEY", 177:"MOVEABOVE",
    178:"MOVETOP", 179:"DAMAGE", 180:"MOUSEDOWN", 181:"MOUSEUP",
    182:"MOUSEENTER", 183:"MOUSEEXIT", 184:"MOUSEMOVE",
    185:"MOUSEDOWN_POS", 186:"MOUSEDOWN_MOD", 187:"AUTOSCROLL",
    188:"OBSCURE", 189:"OPTIMIZED_FOCUS", 190:"SPCL_FOREGROUND",
    191:"SPCL_BACKGROUND", 192:"CWIDTH", 193:"CURSOR_POSITION",
    194:"EDITABLE", 195:"SELECTION", 196:"ALWAYSHOME",
    197:"SECURE", 198:"AUTOSKIP", 199:"CASE_FOLD",
    200:"TYPEOVERMODE", 201:"RENDER", 202:"CAN_TAKE_FOCUS",
    203:"HAS_LOV", 204:"REQUIRED_CHANGE", 205:"REPLACES",
    206:"CLRDIRTY", 207:"CHEIGHT", 208:"WRAP_STYLE",
    209:"VSBARPOLICY", 210:"CONTENT", 211:"DRAWN_AUTOSCROLLED",
    212:"DRAWN_SLOWDRAW", 213:"DRAWN_CANVASUSAGE",
    214:"DRAWN_RESIZED", 215:"DRAWN_MDIFLAG", 216:"WINDOW_CLOSE",
    217:"WINDOW_CONTENT", 218:"WINDOW_HSA", 219:"WINDOW_VSA",
    220:"WINDOW_HTBA", 221:"WINDOW_VTBA", 222:"WINDOW_MODALITY",
    223:"WINDOW_MOUSERELATIVE", 224:"WINDOW_MIN_SIZE",
    225:"WINDOW_MAX_SIZE", 226:"WINDOW_INC_SIZE",
    227:"WINDOW_CAN_RESIZE", 228:"WINDOW_CAN_CLOSE",
    229:"WINDOW_CAN_MOVE", 230:"WINDOW_CAN_MINIMIZE",
    231:"WINDOW_CAN_MAXIMIZE", 232:"WINDOW_CAN_TITLE",
    233:"WINDOW_ICON_IMAGE", 234:"WINDOW_APP_MENU",
    235:"WINDOW_NAVIGATION", 236:"WINSYS_CURSOR",
    237:"WINDOW_COLORPAL", 238:"WINDOW_COLORMAPREDRAW",
    239:"WINDOW_MENU", 240:"WINDOW_BMPAINTABLE",
    241:"WINDOW_LEADER", 242:"WINDOW_MAXIMIZED",
    243:"WINDOW_ICONIFIED", 244:"WINDOW_USE3D",
    245:"WINDOW_PRINT", 246:"WINDOW_RAISE",
    247:"WINDOW_ACTIVATED", 248:"WINDOW_MDI_VTOOLBAR",
    249:"WINDOW_MDI_HTOOLBAR", 250:"SB_SIZE", 251:"SB_LINEINCR",
    252:"SB_PAGEINCR", 253:"SB_SCROLLEE", 254:"SB_HORIZONTAL",
    255:"SB_REVERSEDIR", 256:"SB_ACTION", 257:"SBOX_CONTENT",
    258:"SBOX_HSA", 259:"SBOX_VSA", 260:"SBOX_CONTENTSIZE",
    261:"SBOX_HLABEL", 262:"SBOX_VLABEL",
    263:"INITIAL_RESOLUTION", 264:"INITIAL_DISP_SIZE",
    265:"INITIAL_CMDLINE", 266:"INITIAL_COLOR_DEPTH",
    267:"INITIAL_SCALE_INFO", 268:"INITIAL_VERSION",
    269:"VERSION_TOO_OLD", 270:"VERSION_TOO_NEW",
    271:"INITIAL_ENCRYPTKEY", 272:"SUPPORT_SURROGATE_PAIRS",
    273:"WINSYS_TERMINALFILE", 274:"WINSYS_DEVICENAME",
    275:"WINSYS_NEEDAPPMENU", 276:"WINSYS_SDI",
    277:"WINSYS_TRANSIENTMENU", 278:"WINSYS_BOOTKEYCS",
    279:"MAX_BYTES_PER_CHAR", 280:"WINSYS_DRAWINGDIR",
    281:"WINSYS_LAYOUTDIR", 282:"WINSYS_BEEP",
    283:"WINSYS_HYPERLINK", 284:"WINSYS_COLOR_ADD",
    285:"WINSYS_CONSOLE_MSG", 286:"WINSYS_WORKING_MSG",
    287:"WINSYS_FONT_ADD", 288:"WINSYS_PLAY_TEST",
    290:"WINSYS_LOCALESUPPORT", 291:"WINSYS_REQUIREDVA_LIST",
    292:"WINSYS_SYNC_BUILTIN", 293:"ALERT_NO_MNEMONIC",
    294:"ALERT_ICON", 295:"ALERT_BUTTONS",
    296:"ALERT_DEFAULT_BUTTON", 297:"BP_TYPE", 298:"BP_PARENT",
    299:"BP_STRINGVAL", 300:"BP_BASELINE", 301:"BP_HALIGN",
    302:"BP_VALIGN", 303:"BP_LSTART", 304:"BP_LEND",
    305:"BP_FOREFILLCOL", 306:"BP_BACKFILLCOL",
    307:"BP_FOREEDGECOL", 308:"BP_BACKEDGECOL",
    309:"BP_TEXTCOL", 310:"BP_LINETHICK", 311:"BP_RRECT",
    312:"BP_EDGEPATTERN", 313:"BP_FILLPATTERN",
    314:"BP_LINE_BEVEL", 315:"BP_FONT", 316:"BP_NUMCHUNKS",
    317:"BP_CHUNK", 318:"BP_SCREEN_HORIZONTAL",
    319:"BP_SCREEN_VERTICAL", 320:"BP_VGS_HORIZONTAL",
    321:"BP_VGS_VERTICAL", 322:"BP_VGS_VERSION",
    323:"IS_CANCEL", 324:"IS_DEFAULT", 325:"PRESSED",
    326:"IMAGE", 327:"PLIST_LISTINDEX", 328:"PLIST_LISTITEM",
    329:"PLIST_ADDLISTITEM", 330:"PLIST_DELLISTITEM",
    331:"PLIST_DELLIST", 332:"PLIST_LISTCLOSED", 333:"COUNT",
    334:"SELECTEDINDEX", 335:"SELECT", 336:"DESELECT",
    337:"MAKEVISIBLE", 338:"COMBOBOX_USERITEM", 339:"USERTEXT",
    340:"TLIST_NOSELECTION", 341:"TLIST_ACTIVATED",
    342:"RB_AUTOTABSTOP", 343:"RB_AUTOCOORD",
    344:"RADIOGROUP", 345:"LOCALSTATE", 346:"GROUPLEADER",
    347:"STBAR_ADDLAMP", 348:"STBAR_MSGLINE",
    349:"STBAR_LAMP_INDEX", 350:"STBAR_LAMP_VALUE",
    351:"STBAR_SHOW_WORKING", 352:"STBAR_BLANK_MSG",
    353:"STBAR_MAKE_CURRENT", 354:"MENU_MENUITEM",
    355:"MENU_ACCEL_CODE", 356:"MENU_ACCELERATOR",
    357:"MENU_ACCEL_MOD", 358:"MENU_HELP", 359:"MENU_HIDDEN",
    360:"MENU_ICON", 361:"MENU_ID", 362:"MENU_STARTGROUP",
    363:"MENU_STATE", 364:"MENU_SUBMENU", 365:"MENU_TEAROFF",
    366:"MENU_ENDSUBMENU", 367:"MENU_MENUUPDATE",
    368:"MENU_POPVIEW", 369:"MENU_POPXY", 370:"MENU_CREATEUI",
    371:"MENU_FLAGS", 372:"MENU_NOSMARTBAR",
    373:"TIMER_SCHEDULE", 374:"TIMER_EXPIRED",
    375:"TIMER_CREATE", 376:"FONT_CHARSET", 377:"FONT_SIZE",
    378:"FONT_STYLE", 379:"FONT_WEIGHT", 380:"FONT_WIDTH",
    381:"FONT_IMAGETEXT", 382:"FONT_KERNING", 383:"FONT_NAME",
    384:"IMAGE_URL", 385:"IMAGE_VALUE", 386:"SCALE",
    387:"SCROLL_STYLE", 388:"IMAGE_SELECTRECT",
    389:"IMAGE_SELECTALL", 390:"IMAGE_CUT", 391:"IMAGE_COPY",
    392:"IMAGE_PASTE", 393:"IMAGE_QUALITY", 394:"IMAGE_DITHER",
    395:"SCROLL_POSITION", 396:"VIEWPORT_SIZE",
    397:"CLASSNAME", 398:"EVENT", 399:"EVENTNAME",
    400:"EVENT_ARGNAME", 401:"EVENT_ARGVALUE",
    402:"CUSTOM_PROPERTY", 403:"CUSTOM_PROPERTY_NAME",
    404:"CUSTOM_PROPERTY_VALUE", 405:"CLIPBOARD_CLEAR",
    406:"CLIPBOARD_GET", 407:"CLIPBOARD_SET",
    408:"CLIPBOARD_LENGTH", 409:"POPUPHELP_STRING",
    410:"POPUPHELP_ID", 411:"TAB_TOPPAGE", 412:"TAB_TABSIDE",
    413:"TAB_PAGEINFO", 414:"TAB_PAGENUM", 415:"TAB_PAGEID",
    416:"PROMPTLIST_CANVAS", 417:"PROMPTLIST_ADD_PROMPT_ID",
    418:"PROMPTLIST_REMOVE_PROMPT",
    419:"PROMPTLIST_UPDATE_PROMPT_ID",
    420:"PROMPTLIST_DONE_PROMPT", 421:"PROMPT_ENUM",
    422:"PROMPT_EOF", 423:"PROMPT_AOF", 424:"PROMPT_LINECOUNT",
    425:"PROMPT_COLORNUM", 426:"PROMPT_FONTNUM",
    427:"PROMPT_ITEMPOS", 428:"PROMPT_ITEMSIZE",
    429:"PROMPT_BGPATTERN", 430:"LOGON_USERNAME_LABEL",
    431:"LOGON_PASSWORD_LABEL", 432:"LOGON_DATABASE_LABEL",
    433:"LOGON_USERNAME_VALUE", 434:"LOGON_PASSWORD_VALUE",
    435:"LOGON_DATABASE_VALUE", 436:"LOGON_OLDPASSWORD_LABEL",
    437:"LOGON_NEWPASSWORD_LABEL",
    438:"LOGON_RETYPE_PASSWORD_LABEL",
    439:"LOGON_OLDPASSWORD_VALUE", 440:"LOGON_NEWPASSWORD_VALUE",
    441:"LOGON_RETYPE_PASSWORD_VALUE",
    442:"DISPERR_SQL_LABEL", 443:"DISPERR_ERROR_LABEL",
    444:"DISPERR_SQL_VALUE", 445:"DISPERR_ERROR_VALUE",
    446:"LOV_ROWS", 447:"LOV_AUTOSIZECOLS",
    448:"LOV_DEFINECOL", 449:"LOV_COLRALIGN",
    450:"LOV_SELECTION", 451:"LOV_REQUEST_ROW",
    452:"LOV_AUTOREDUCECHAR", 453:"LOV_UNREDUCE",
    454:"LOV_FIND_VAL", 455:"LOV_LONGLIST_LABEL",
    456:"LOV_NOTLONGLIST", 457:"EDITOR_BOTTOM_TITLE",
    458:"EDITOR_VALUE_REQD", 459:"EDITOR_VSCROLL",
    460:"EDITOR_SCROLLBAR", 461:"EDITOR_MULTILINE",
    462:"EDITOR_PESRCHREP", 463:"EDITOR_PESRCHFOR",
    464:"EDITOR_PEREPLWTH", 465:"EDITOR_PEREPLACE",
    466:"EDITOR_PEREPALL", 467:"EDITOR_PECONTBEGIN",
    468:"EDITOR_PECONTINUE", 469:"EDITOR_PEENDREG",
    470:"EDITOR_PENOMATCH", 471:"PARAM_MUSTFILL",
    472:"PARAM_REQUIRED", 473:"PARAM_NUM_DISPLAYED",
    474:"PARAM_ERR_REQUIRED", 475:"PARAM_ERR_MUSTFILL",
    476:"EVENT_ALERT_DISMISS", 477:"EVENT_MENU",
    478:"EVENT_WINSYS", 479:"EVENT_SCROLL",
    480:"EVENT_WINDOW_FINAL", 481:"EVENT_SHOWOPTIONS",
    482:"EVENT_DELIMAGE", 483:"EVENT_USER_DEFINED",
    484:"NODE_STATE", 485:"NUM_CHILD_NODES",
    486:"NUM_SELECTED", 487:"SELECT_NODE",
    488:"EVENT_SELECTED", 489:"EVENT_EXPANDED",
    490:"EVENT_COLLAPSED", 491:"EVENT_ACTIVATED",
    492:"EVENT_DESELECTED", 493:"REQUESTED_EVENTS",
    494:"ADD_NODE", 495:"DELETE_NODE", 496:"MULTI_SELECT",
    497:"SHOW_LINES", 498:"SHOW_SYMBOLS", 499:"ALTER_NODE",
    500:"NODE_ID", 501:"TREE_FREEZE", 502:"NODE_ANCHOR",
    503:"NODE_OFFSET", 504:"NODE_SELECTION", 505:"NODE_DATA",
    506:"NUM_CHILDREN", 507:"RESET_CHILDREN",
    508:"JHELP_TOPICID", 509:"HBOOK_TITLE",
    510:"SERVER_USER_PARAMS", 511:"ALL_PROPERTIES",
    512:"ALL_LISTENERS", 513:"ACCESSIBILITY_SUPPORT",
    514:"ACCESSIBILITY_DESC", 515:"ACCESSIBILITY_NAME",
    516:"KEYBINDING", 517:"HEARTBEAT", 518:"SB_NONBLOCKING",
    519:"LATENCY_CHECK", 520:"DELETE_CHILDREN",
    521:"FOCUSLIST_REMOVE", 522:"STBAR_REMOVE_LAMPS",
    523:"CTIME_MESSAGE", 524:"CTIME_ENABLE", 525:"NLS_LANG",
    526:"ASYNC_MESSAGE", 527:"UPDATE_ASYNC_PROCESSING",
    528:"MAX_LENGTH_IS_BYTES", 529:"DATETIME_LOCAL_TZ",
    530:"DEFAULT_LOCAL_TZ", 531:"OK_TO_PASTE",
    532:"SELECTION_START", 533:"SELECTION_END",
    534:"STOP_QUERY_LABEL", 535:"RT_MSE_PRSD_NODE",
    536:"MONITOR", 537:"ROWLOCK_REQUIRED",
    538:"WINSYS_RECORD_NAMES", 539:"WINDOW_NAME",
    540:"MONITOR_START", 541:"BLOCK_SCROLLER_ID",
    546:"JAVASCRIPT_EVENT", 547:"JAVASCRIPT_EVENT_NAME",
    548:"JAVASCRIPT_EVENT_VALUE",
    549:"WINSYS_JS_EXPRESSION", 550:"JAVASCRIPT_ENABLED",
    551:"MULTIBYTE_MNEMONIC",
    552:"JAVASCRIPT_BLOCKS_HEARTBEAT",
    553:"JAVASCRIPT_DONE", 554:"JAVASCRIPT_RETURN_VALUE",
    555:"MOUSE_DOWN_MSG_SENT", 556:"FOCUS_LOG",
    557:"FOCUS_WARNING", 558:"MESSAGE_RUEI_BEGIN",
    559:"MESSAGE_RUEI_END", 560:"CLIENT_IDLE_EXPIRED",
    561:"CLIENT_IDLE_DURATION", 562:"MAX_EVENT_WAIT",
    563:"SSO_LOGOUT", 564:"WEBSTART_SESSION",
    565:"STAND_ALONE_APP", 566:"PLAY_AUDIO", 567:"QUIET",
    568:"GRADIENT", 569:"BACKGROUND_IMAGE_VALUE",
    570:"BACKGROUND_IMAGE_FIXED_SIZE",
}

# IDs whose string values are security-sensitive
SENSITIVE_IDS = {131, 433, 434, 435, 439, 440, 441, 444, 445}

ACTION_MAP = {
    1: "CREATE", 2: "UPDATE", 3: "DESTROY", 4: "GET",
    5: "ACTION_5", 6: "ACTION_6", 7: "CLIENT_GET", 8: "CLIENT_SET",
}

GDAY = 0x47446179
MATE = 0x4d617465


# ── Utilities ─────────────────────────────────────────────────────────────────

def to_bytes(java_bytes):
    """Convert Java byte[] (signed) to Python 2 bytes (str)."""
    if java_bytes is None:
        return b''
    if isinstance(java_bytes, (bytes, bytearray)):
        return bytes(java_bytes)
    return bytes(bytearray([b & 0xFF for b in java_bytes]))


def java_shr(val, shift):
    """Java arithmetic right shift on a 32-bit signed integer."""
    val = val & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val >> shift


def derive_key(client_random, server_random):
    """5-byte RC4 key from GDay/Mate randoms (from HTTPConnection.class)."""
    c = struct.unpack('>i', client_random[:4])[0]
    s = struct.unpack('>i', server_random[:4])[0]
    return bytes(bytearray([
        java_shr(c, 8)  & 0xFF,
        java_shr(s, 4)  & 0xFF,
        0xAE,
        java_shr(c, 16) & 0xFF,
        java_shr(s, 12) & 0xFF,
    ]))


def get_jsessionid(url_str):
    m = re.search(r'jsessionid=([A-Za-z0-9!_\-]+)', url_str)
    return m.group(1) if m else None


def get_pragma(headers):
    for h in headers:
        hs = str(h)
        if hs.lower().startswith('pragma:'):
            return hs.split(':', 1)[1].strip()
    return None


# ── Stateful RC4 ──────────────────────────────────────────────────────────────

def rc4_init(key):
    """Return mutable RC4 state: [S_list, i, j]."""
    S = list(range(256))
    j = 0
    kb = bytearray(key)
    for i in range(256):
        j = (j + S[i] + kb[i % len(kb)]) % 256
        S[i], S[j] = S[j], S[i]
    return [S, 0, 0]


def rc4_apply(state, data):
    """Decrypt/encrypt data using mutable RC4 state (advances state in-place)."""
    S = state[0]
    si = state[1]
    sj = state[2]
    out = bytearray()
    for b in bytearray(data):
        si = (si + 1) % 256
        sj = (sj + S[si]) % 256
        S[si], S[sj] = S[sj], S[si]
        out.append(b ^ S[(S[si] + S[sj]) % 256])
    state[1] = si
    state[2] = sj
    return bytes(out)


# ── FHT Binary Protocol Parser ────────────────────────────────────────────────

class _EOF(Exception):
    pass


class _Stream(object):
    def __init__(self, data):
        self._buf = io.BytesIO(data)

    def rb(self):
        b = self._buf.read(1)
        if not b:
            raise _EOF()
        v = b[0]
        return v if isinstance(v, int) else ord(v)

    def read(self, n):
        d = self._buf.read(n)
        if len(d) < n:
            raise _EOF()
        return d

    def peek(self):
        pos = self._buf.tell()
        b = self._buf.read(1)
        self._buf.seek(pos)
        if not b:
            return -1
        v = b[0]
        return v if isinstance(v, int) else ord(v)


def _read_utf(s):
    ln = struct.unpack('>H', s.read(2))[0]
    raw = s.read(ln)
    try:
        return raw.decode('utf-8', 'replace')
    except Exception:
        return u'<binary>'


def _read_opt_uint(s):
    i = s.rb()
    j = s.rb()
    if i & 0x80:
        m = s.rb()
        n = s.rb()
        i &= 0x7F
        return (i << 24) | (j << 16) | (m << 8) | n
    return (i << 8) | j


def _skip_extended(s, subtype, str_dict):
    if subtype == 2:                    # String[]
        n = struct.unpack('>i', s.read(4))[0]
        for _ in range(max(0, n)):
            _read_utf(s)
    elif subtype == 4:                  # Character (2 bytes)
        s.read(2)
    elif subtype == 5:                  # Float
        s.read(4)
    elif subtype == 6:                  # Date / Long
        s.read(8)
    elif subtype in (7, 15):            # byte[]
        n = struct.unpack('>i', s.read(4))[0]
        s.read(max(0, n))
    elif subtype == 8:                  # Nested Message
        _read_props(s, str_dict)
    elif subtype == 10:                 # Rectangle
        s.read(8)


def _read_props(s, str_dict):
    props = []
    while True:
        b0 = s.rb()
        if b0 == 0xF0:
            break
        if (b0 & 0xF0) == 0xB0:
            props.append(('TAG', 'tag', b0 & 0x0F))
            continue
        if (b0 & 0xF0) == 0xD0:
            mask = struct.unpack('>H', s.read(2))[0]
            props.append(('DELETEMASK', 'delete_mask', mask))
            continue
        b1 = s.rb()
        combined = (b0 << 8) | b1
        tm  = combined & 0xF000
        pid = combined & 0x0FFF
        name = ID_MAP.get(pid, 'ID_%d' % pid)

        if   tm == 0x0000:
            v = struct.unpack('>i', s.read(4))[0]
            props.append((name, 'int', v))
        elif tm == 0x1000:
            props.append((name, 'int', 0))
        elif tm == 0x2000:
            props.append((name, 'int', s.rb()))
        elif tm == 0x3000:
            v = struct.unpack('>H', s.read(2))[0]
            props.append((name, 'int', v))
        elif tm == 0x4000:
            di   = s.rb()
            text = _read_utf(s)
            if 0 <= di < len(str_dict):
                str_dict[di] = text
            props.append((name, 'str', text))
        elif tm == 0x5000:
            props.append((name, 'bool', True))
        elif tm == 0x6000:
            props.append((name, 'bool', False))
        elif tm == 0x7000:
            v = struct.unpack('>b', s.read(1))[0]
            props.append((name, 'byte', v))
        elif tm == 0x8000:
            props.append((name, 'void', None))
        elif tm == 0x9000:
            dst = s.rb(); src = s.rb()
            text = str_dict[src] if 0 <= src < len(str_dict) else u''
            if 0 <= dst < len(str_dict):
                str_dict[dst] = text
            props.append((name, 'str', text))
        elif tm == 0xA000:
            x, y = struct.unpack('>hh', s.read(4))
            props.append((name, 'point', (x, y)))
        elif tm == 0xC000:
            x, y = s.rb(), s.rb()
            props.append((name, 'bpoint', (x, y)))
        elif tm == 0xE000:
            st = struct.unpack('>b', s.read(1))[0]
            _skip_extended(s, st, str_dict)
            props.append((name, 'ext_%d' % st, None))
        else:
            props.append((name, 'unk_%04x' % tm, None))
    return props


def _read_message(s, str_dict):
    b0 = s.rb()
    if b0 == 0xF0:
        return None
    m = b0 << 8
    if (m & 0xF000) in (0x0000, 0x4000):
        b1 = s.rb()
        i  = m | b1
    else:
        i  = m
    an = i & 0xF000
    action_tbl = {0:1, 0x1000:2, 0x2000:3, 0x3000:4,
                  0x4000:5, 0x5000:6, 0x6000:7, 0x7000:8}
    action_num  = action_tbl.get(an, 0)
    action_name = ACTION_MAP.get(action_num, 'ACTION_%d' % action_num)
    if action_num in (5, 6):
        s.rb()  # delta_index
    class_id   = i & 0x3FF
    if class_id >= 2000:
        class_id += 3000
    handler_id = _read_opt_uint(s)
    props      = _read_props(s, str_dict)
    return {'action': action_name, 'class_id': class_id,
            'handler_id': handler_id, 'props': props}


def parse_fht(data):
    """Parse a decrypted FHT packet. Returns list of message dicts."""
    s = _Stream(data)
    str_dict = [u''] * 256
    messages = []
    try:
        while True:
            if s.peek() < 0:
                break
            msg = _read_message(s, str_dict)
            if msg is None:
                break
            messages.append(msg)
    except Exception:
        pass
    return messages


def format_decoded(pragma, direction, data_len, messages):
    """Build human-readable text for the Oracle Forms tab."""
    lines = []
    dir_str = 'REQUEST' if direction == 'req' else 'RESPONSE'
    lines.append(u'Pragma %d  %s  (%d bytes)' % (pragma, dir_str, data_len))
    lines.append(u'=' * 60)

    if not messages:
        lines.append(u'(no FHT messages parsed)')
        return u'\n'.join(lines)

    # Collect sensitive values for summary at top
    sensitive_found = []
    for msg in messages:
        for name, typ, val in msg['props']:
            pid = next((k for k, v in ID_MAP.items() if v == name), None)
            if pid in SENSITIVE_IDS and typ == 'str' and val:
                sensitive_found.append((name, val))

    if sensitive_found:
        lines.append(u'')
        lines.append(u'*** SENSITIVE VALUES FOUND ***')
        for sname, sval in sensitive_found:
            lines.append(u'  %-32s "%s"' % (sname, sval))
        lines.append(u'=' * 60)

    lines.append(u'%d message(s):' % len(messages))
    lines.append(u'')

    for i, msg in enumerate(messages):
        lines.append(u'[%d] %s  cls=%d  hnd=0x%04x' % (
            i, msg['action'], msg['class_id'], msg['handler_id']))
        for name, typ, val in msg['props']:
            pid = next((k for k, v in ID_MAP.items() if v == name), None)
            sensitive = pid in SENSITIVE_IDS if pid else False
            if   typ == 'str':
                display = u'"%s"' % val
            elif typ in ('int', 'byte'):
                display = unicode(val)
            elif typ == 'bool':
                display = unicode(val)
            elif typ == 'point':
                display = u'(%d,%d)' % (val[0], val[1])
            elif typ == 'bpoint':
                display = u'(%d,%d)' % (val[0], val[1])
            elif typ == 'void':
                display = u'<void>'
            else:
                display = u'<%s>' % typ
            marker = u'  <-- SENSITIVE' if sensitive else u''
            lines.append(u'    %-32s %s%s' % (name, display, marker))
        lines.append(u'')

    return u'\n'.join(lines)


# ── FHT String Patcher (for JWT-style editing) ────────────────────────────────

def _extract_str_props(text):
    """Return [(name, value, occurrence_of_name)] for STRING props in decoded text."""
    result = []
    counts = {}
    for line in text.split(u'\n'):
        m = re.match(r'^\s+(\w+)\s+"(.*?)"(?:\s|$)', line)
        if m:
            name = m.group(1)
            val  = m.group(2)
            occ  = counts.get(name, 0)
            counts[name] = occ + 1
            result.append((name, val, occ))
    return result


def _patch_string_prop(plain, prop_id, new_value, occurrence=0):
    """Replace occurrence-th STRING property value in FHT binary. Returns new bytes."""
    data   = bytearray(plain)
    hdr_hi = (0x40 | ((prop_id >> 8) & 0x0F)) & 0xFF
    hdr_lo = prop_id & 0xFF
    count  = 0
    i      = 0
    while i < len(data) - 4:
        if data[i] == hdr_hi and data[i+1] == hdr_lo:
            if count == occurrence:
                old_len  = (data[i+3] << 8) | data[i+4]
                new_bytes = bytearray(new_value.encode('utf-8'))
                new_len  = len(new_bytes)
                data = (data[:i+3] +
                        bytearray([(new_len >> 8) & 0xFF, new_len & 0xFF]) +
                        new_bytes +
                        data[i+5+old_len:])
                return bytes(data)
            count += 1
        i += 1
    return bytes(data)


def _build_patched_plain(plain, orig_text, edited_text):
    """Diff original vs edited decoded text; patch changed STRING values into plaintext."""
    orig_props = _extract_str_props(orig_text)
    edit_props = _extract_str_props(edited_text)

    # Build {(name, occ): value} maps
    def _index(props):
        d = {}
        for name, val, occ in props:
            d[(name, occ)] = val
        return d

    orig_map = _index(orig_props)
    edit_map = _index(edit_props)

    result = plain
    for key in orig_map:
        name, occ = key
        if key in edit_map and orig_map[key] != edit_map[key]:
            pid = next((k for k, v in ID_MAP.items() if v == name), None)
            if pid is not None:
                result = _patch_string_prop(result, pid, edit_map[key], occ)
    return result


def parse_mod_rules(text):
    """Parse rules text → {prop_name: new_value}."""
    rules = {}
    for line in text.split(u'\n'):
        line = line.strip()
        if not line or line.startswith(u'#'):
            continue
        if u'=' not in line:
            continue
        name, _, val = line.partition(u'=')
        name = name.strip()
        val  = val.strip()
        if val.startswith(u'"') and val.endswith(u'"'):
            val = val[1:-1]
        if name:
            rules[name] = val
    return rules


def _apply_rules_to_plain(pt, rules):
    """Apply {prop_name: new_value} rules to FHT plaintext bytes."""
    result = pt
    for prop_name, new_val in rules.items():
        pid = next((k for k, v in ID_MAP.items() if v == prop_name), None)
        if pid is not None:
            result = _patch_string_prop(result, pid, new_val, 0)
    return result


# ── Session State ──────────────────────────────────────────────────────────────

class SessionState(object):
    def __init__(self, key):
        self.key     = key
        self.req_st  = rc4_init(key)   # mutable, advances per request
        self.rsp_st  = rc4_init(key)   # mutable, advances per response

# Thread-safe global storage
_lock      = threading.Lock()
_sessions  = {}   # jsessionid  -> SessionState
_pending   = {}   # jsessionid  -> client_random bytes (waiting for Pragma 1 response)
_decoded   = {}   # (jsid, pragma, 'req'/'rsp') -> decoded text (unicode)
_plain       = {}   # (jsid, pragma, 'req'/'rsp') -> plaintext bytes (for re-encoding)
_pre_state   = {}   # (jsid, pragma, 'req'/'rsp') -> RC4 state snapshot before this pragma
_tab_refs    = []   # strong refs to OracleFormsTab instances (prevent Jython GC)
_live_msgs   = {}   # (jsid, pragma) -> IInterceptedProxyMessage (for Apply & Forward)
_mod_rules      = {}    # prop_name -> new_value  (auto-applied in processProxyMessage)
_session_log    = []    # log entries shown in OF Rules tab
_rules_tab_ref  = [None]  # [OracleFormsRulesTab] strong ref for cross-class access


# ── Rules Tab ─────────────────────────────────────────────────────────────────

class OracleFormsRulesTab(ITab):
    """Standalone Burp tab for managing auto-modification rules."""

    def __init__(self, callbacks):
        self._callbacks = callbacks

        self._area = JTextArea()
        self._area.setFont(Font('Monospaced', Font.PLAIN, 12))
        self._area.setText(
            u'# Oracle Forms Auto-Modify Rules\n'
            u'# Format:  PROPERTY_NAME = new_value\n'
            u'# Rules are applied to every matching Oracle Forms REQUEST automatically.\n'
            u'# Leave blank or comment out lines to disable.\n'
            u'#\n'
            u'# Examples:\n'
            u'# VALUE = injected_value\n'
            u'# LOGON_USERNAME_VALUE = admin\n'
            u'# LOGON_PASSWORD_VALUE = password123\n'
        )

        tab = self

        class _Apply(ActionListener):
            def actionPerformed(self, e):
                rules = parse_mod_rules(unicode(tab._area.getText()))
                with _lock:
                    _mod_rules.clear()
                    _mod_rules.update(rules)
                out = callbacks.getStdout()
                print >> out, '[OracleForms] %d rule(s) active: %s' % (
                    len(rules), list(rules.keys()))

        class _Clear(ActionListener):
            def actionPerformed(self, e):
                with _lock:
                    _mod_rules.clear()
                out = callbacks.getStdout()
                print >> out, '[OracleForms] Rules cleared.'

        apply_btn = JButton('Apply Rules')
        apply_btn.addActionListener(_Apply())
        clear_btn = JButton('Clear Rules')
        clear_btn.addActionListener(_Clear())

        self._status = JLabel('  Rules inactive.')
        btn_panel = JPanel()
        btn_panel.add(apply_btn)
        btn_panel.add(clear_btn)
        btn_panel.add(self._status)

        rules_panel = JPanel(BorderLayout())
        rules_panel.add(JLabel('  Modification Rules:'), BorderLayout.NORTH)
        rules_panel.add(JScrollPane(self._area), BorderLayout.CENTER)
        rules_panel.add(btn_panel, BorderLayout.SOUTH)

        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font('Monospaced', Font.PLAIN, 11))

        log_panel = JPanel(BorderLayout())
        log_panel.add(JLabel('  Session Log:'), BorderLayout.NORTH)
        log_panel.add(JScrollPane(self._log_area), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, rules_panel, log_panel)
        split.setResizeWeight(0.65)
        self._panel = split

    def append_log(self, msg):
        import time
        line = u'[%s] %s\n' % (time.strftime('%H:%M:%S'), unicode(msg))
        log_area = self._log_area
        class _A(Runnable):
            def run(self):
                log_area.append(line)
        SwingUtilities.invokeLater(_A())

    def getTabCaption(self):
        return 'OF Rules'

    def getUiComponent(self):
        return self._panel


# ── Burp Extension ────────────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, IProxyListener, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerProxyListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        self._rules_tab    = OracleFormsRulesTab(callbacks)
        _rules_tab_ref[0]  = self._rules_tab
        callbacks.addSuiteTab(self._rules_tab)
        sys = callbacks.getStdout()
        print >> sys, '[OracleForms] Extension loaded. Waiting for Oracle Forms traffic...'

    # ── IProxyListener ────────────────────────────────────────────────────

    def processProxyMessage(self, messageIsRequest, message):
        try:
            info     = message.getMessageInfo()
            req_raw  = to_bytes(info.getRequest())
            req_info = self._helpers.analyzeRequest(info.getHttpService(), req_raw)
            url_str  = str(req_info.getUrl())

            if 'lservlet' not in url_str:
                return

            headers    = req_info.getHeaders()
            pragma_str = get_pragma(headers)
            if pragma_str is None:
                return
            if not pragma_str.isdigit():
                return

            pragma = int(pragma_str)
            jsid   = get_jsessionid(url_str)
            if not jsid:
                return

            body_off = req_info.getBodyOffset()
            req_body = req_raw[body_off:]

            if messageIsRequest:
                with _lock:
                    _live_msgs[(jsid, pragma)] = message
                body_to_process = req_body
                if pragma >= 3:
                    mod = self._try_mod_rules(jsid, pragma, req_body, req_info, req_raw)
                    if mod is not None:
                        info.setRequest(mod[0])
                        body_to_process = mod[1]
                self._on_request(jsid, pragma, body_to_process)
            else:
                rsp_raw = to_bytes(info.getResponse())
                if rsp_raw:
                    rsp_info = self._helpers.analyzeResponse(rsp_raw)
                    rsp_body = rsp_raw[rsp_info.getBodyOffset():]
                    self._on_response(jsid, pragma, req_body, rsp_body)
                    if pragma >= 3:
                        self._flag_sensitive(info, jsid, pragma)

        except Exception as e:
            pass  # don't crash Burp on parse errors

    def _flag_sensitive(self, info, jsid, pragma):
        """Highlight request in Proxy History red if sensitive values found; log them."""
        try:
            with _lock:
                req_text = _decoded.get((jsid, pragma, 'req'), u'')
                rsp_text = _decoded.get((jsid, pragma, 'rsp'), u'')
            combined = req_text + rsp_text
            if u'SENSITIVE' not in combined:
                return
            found = re.findall(r'(\w+)\s+"([^"]*?)"\s+<-- SENSITIVE', combined)
            if not found:
                return
            comment = u', '.join(u'%s="%s"' % (k, v[:40]) for k, v in found)
            info.setComment(comment)
            info.setHighlight('red')
            rt = _rules_tab_ref[0]
            if rt:
                rt.append_log(u'[SENSITIVE] Pragma %d  ...%s  %s' % (pragma, jsid[-12:], comment))
        except:
            pass

    def _try_mod_rules(self, jsid, pragma, body, req_info, req_raw):
        """If _mod_rules set and session exists, patch+re-encrypt body.
        Returns (new_full_request_bytes, new_body_bytes) or None."""
        with _lock:
            rules = dict(_mod_rules)
            sess  = _sessions.get(jsid)
        if not rules or sess is None:
            return None
        with _lock:
            state_copy = [list(sess.req_st[0]), sess.req_st[1], sess.req_st[2]]
        pt          = rc4_apply(state_copy, body)
        modified_pt = _apply_rules_to_plain(pt, rules)
        if modified_pt == pt:
            return None
        with _lock:
            re_state = [list(sess.req_st[0]), sess.req_st[1], sess.req_st[2]]
        new_ct  = rc4_apply(re_state, modified_pt)
        headers = list(req_info.getHeaders())
        for idx, h in enumerate(headers):
            if str(h).lower().startswith('content-length:'):
                headers[idx] = 'Content-Length: %d' % len(new_ct)
                break
        new_req = self._helpers.buildHttpMessage(headers, new_ct)
        stdout  = self._callbacks.getStdout()
        print >> stdout, '[OracleForms] Rule applied on Pragma %d' % pragma
        return (new_req, new_ct)

    def _on_request(self, jsid, pragma, body):
        with _lock:
            if pragma == 1:
                if len(body) >= 8:
                    magic = struct.unpack('>I', body[:4])[0]
                    if magic == GDAY:
                        _pending[jsid] = body[4:8]
            elif pragma >= 3:
                sess = _sessions.get(jsid)
                if sess is None:
                    return
                pre = [list(sess.req_st[0]), sess.req_st[1], sess.req_st[2]]
                pt  = rc4_apply(sess.req_st, body)
                _pre_state[(jsid, pragma, 'req')] = pre
                _plain[(jsid, pragma, 'req')]     = pt
                msgs = parse_fht(pt)
                text = format_decoded(pragma, 'req', len(body), msgs)
                _decoded[(jsid, pragma, 'req')]   = text

    def _on_response(self, jsid, pragma, req_body, rsp_body):
        with _lock:
            if pragma == 1:
                if len(rsp_body) >= 8:
                    magic = struct.unpack('>I', rsp_body[:4])[0]
                    if magic == MATE:
                        sr = rsp_body[4:8]
                        cr = _pending.pop(jsid, None)
                        if cr:
                            key  = derive_key(cr, sr)
                            _sessions[jsid] = SessionState(key)
                            msg = u'Key derived  jsid=...%s  key=%s' % (jsid[-12:], key.encode('hex'))
                            rt = _rules_tab_ref[0]
                            if rt: rt.append_log(msg)
            elif pragma >= 3:
                sess = _sessions.get(jsid)
                if sess is None:
                    return
                pre = [list(sess.rsp_st[0]), sess.rsp_st[1], sess.rsp_st[2]]
                pt  = rc4_apply(sess.rsp_st, rsp_body)
                _pre_state[(jsid, pragma, 'rsp')] = pre
                _plain[(jsid, pragma, 'rsp')]     = pt
                msgs = parse_fht(pt)
                text = format_decoded(pragma, 'rsp', len(rsp_body), msgs)
                _decoded[(jsid, pragma, 'rsp')]   = text

    # ── IMessageEditorTabFactory ──────────────────────────────────────────

    def createNewInstance(self, controller, editable):
        tab = OracleFormsTab(self._helpers, controller)
        _tab_refs.append(tab)
        return tab


# ── Message Editor Tab ────────────────────────────────────────────────────────

class OracleFormsTab(IMessageEditorTab):

    def __init__(self, helpers, controller):
        self._helpers    = helpers
        self._controller = controller

        self._area = JTextArea()
        self._area.setEditable(False)
        self._area.setFont(Font('Monospaced', Font.PLAIN, 12))
        self._area.setLineWrap(False)
        self._area.setTabSize(4)

        self._original_text    = u''
        self._original_content = None
        self._jsid             = None
        self._pragma           = None
        self._direction        = None

        self._btn = JButton('Apply & Forward')
        self._btn.setVisible(False)
        tab = self

        class _BtnListener(ActionListener):
            def actionPerformed(self, e):
                tab._apply_and_forward()

        self._btn.addActionListener(_BtnListener())

        # Right-click → Add selected property to OF Rules
        popup = JPopupMenu()
        add_item = JMenuItem('Add selected value to OF Rules')
        popup.add(add_item)

        class _AddRule(ActionListener):
            def actionPerformed(self, e):
                sel = tab._area.getSelectedText()
                if not sel:
                    return
                m = re.search(r'(\w+)\s+"([^"]*)"', unicode(sel))
                if not m:
                    return
                prop, val = m.group(1), m.group(2)
                rt = _rules_tab_ref[0]
                if rt:
                    cur = unicode(rt._area.getText()).rstrip()
                    rt._area.setText(cur + u'\n%s = %s' % (prop, val))
                    rt.append_log(u'Rule added from tab: %s = %s' % (prop, val))

        add_item.addActionListener(_AddRule())

        class _PopupTrigger(MouseAdapter):
            def mousePressed(self, e):
                if e.isPopupTrigger():
                    popup.show(e.getComponent(), e.getX(), e.getY())
            def mouseReleased(self, e):
                if e.isPopupTrigger():
                    popup.show(e.getComponent(), e.getX(), e.getY())

        self._area.addMouseListener(_PopupTrigger())

        south = JPanel()
        south.setLayout(BoxLayout(south, BoxLayout.X_AXIS))
        south.add(self._btn)

        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._area), BorderLayout.CENTER)
        self._panel.add(south, BorderLayout.SOUTH)

    def getTabCaption(self):
        return 'Oracle Forms'

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        """Show tab only for Oracle Forms lservlet POSTs."""
        try:
            svc = self._controller.getHttpService()
            req = to_bytes(self._controller.getRequest())
            if not req:
                return False
            info = self._helpers.analyzeRequest(svc, req)
            url     = str(info.getUrl())
            headers = info.getHeaders()
            return 'lservlet' in url and get_pragma(headers) is not None
        except Exception:
            return False
        except:
            return False

    def setMessage(self, content, isRequest):
        """Called when user selects a message in Proxy History."""
        try:
            req_raw  = to_bytes(self._controller.getRequest())
            req_info = self._helpers.analyzeRequest(self._controller.getHttpService(), req_raw)
            url_str  = str(req_info.getUrl())
            headers  = req_info.getHeaders()

            jsid       = get_jsessionid(url_str)
            pragma_str = get_pragma(headers)

            if not jsid or not pragma_str or not pragma_str.isdigit():
                self._area.setEditable(False)
                self._show(u'Not an Oracle Forms request.')
                return

            pragma    = int(pragma_str)
            direction = 'req' if isRequest else 'rsp'

            self._original_content = content
            self._jsid             = jsid
            self._pragma           = pragma
            self._direction        = direction

            with _lock:
                text        = _decoded.get((jsid, pragma, direction))
                has_session = jsid in _sessions

            if text:
                self._original_text = text
                editable = (direction == 'req')
                self._area.setEditable(editable)
                self._btn.setVisible(editable)
                self._show(text)
                return

            self._original_text = u''
            self._area.setEditable(False)
            self._btn.setVisible(False)

            if pragma == 0:
                self._show(u'Pragma 0: GET request (no encrypted body).')
            elif pragma == 1:
                self._show(
                    u'Pragma 1: GDay/Mate handshake (cleartext).\n'
                    u'Key will be derived from client_random + server_random.\n\n'
                    u'REQ body: ' + req_raw[req_info.getBodyOffset():].encode('hex'))
            elif not has_session:
                self._show(
                    u'[!] No session state for this jsessionid.\n\n'
                    u'The RC4 key has not been captured yet.\n'
                    u'Restart Oracle Forms with Burp proxy running\n'
                    u'to capture the Pragma 1 handshake and derive the key.')
            else:
                self._show(
                    u'[!] Pragma %d decoded data not available.\n\n'
                    u'A preceding Pragma may be missing from the capture.\n'
                    u'Oracle Forms uses a CONTINUOUS RC4 stream:\n'
                    u'if any Pragma is missing, subsequent ones cannot be decoded.' % pragma)

        except Exception as e:
            self._show(u'Error: ' + unicode(str(e)))

    def isModified(self):
        if not self._original_text or self._direction != 'req':
            return False
        return self._area.getText() != self._original_text

    def getMessage(self):
        if not self.isModified():
            return self._original_content
        try:
            with _lock:
                plain = _plain.get((self._jsid, self._pragma, 'req'))
                pre   = _pre_state.get((self._jsid, self._pragma, 'req'))
            if plain is None or pre is None:
                return self._original_content

            edited    = self._area.getText()
            new_plain = _build_patched_plain(plain, self._original_text, edited)

            state_copy = [list(pre[0]), pre[1], pre[2]]
            new_ct     = rc4_apply(state_copy, new_plain)

            req_info = self._helpers.analyzeRequest(
                self._controller.getHttpService(),
                to_bytes(self._original_content))
            headers  = list(req_info.getHeaders())
            for idx, h in enumerate(headers):
                if str(h).lower().startswith('content-length:'):
                    headers[idx] = 'Content-Length: %d' % len(new_ct)
                    break
            return self._helpers.buildHttpMessage(headers, new_ct)
        except:
            return self._original_content

    def getSelectedData(self):
        sel = self._area.getSelectedText()
        if sel:
            return sel.encode('utf-8')
        return None

    def _apply_and_forward(self):
        """Re-encode edited content, write back to intercepted message, forward it."""
        try:
            new_msg = self.getMessage()
            if new_msg is None:
                return
            with _lock:
                live = _live_msgs.get((self._jsid, self._pragma))
            if live is not None:
                live.getMessageInfo().setRequest(new_msg)
                # ACTION_FOLLOW_RULES = 0
                live.setInterceptAction(0)
            self._original_text = unicode(self._area.getText())
            self._btn.setVisible(False)
        except Exception as e:
            self._show(u'Apply error: ' + unicode(str(e)))

    def _show(self, text):
        final = text if isinstance(text, unicode) else text.decode('utf-8', 'replace')
        self._area.setText(final)
        self._area.setCaretPosition(0)
