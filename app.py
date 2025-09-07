import os, io, re, textwrap
import streamlit as st
import openai
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# Install: pip install tree_sitter tree_sitter_languages
try:
    from tree_sitter import Language, Parser
    import tree_sitter_languages as tsl
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False

openai.api_key = os.getenv("OPENAI_API_KEY")

# Shared helpers
def add_issue(issues, category, severity, message, line_no=None, evidence=None, remediation=None, rule_id=None):
    issues.append({
        "id": rule_id or f"{category[:3].upper()}-{len(issues)+1}",
        "category": category,
        "severity": severity,  
        "message": message,
        "line": line_no,
        "evidence": evidence,
        "remediation": remediation
    })

def snippet(full_text, line_no, pad=1):
    lines = full_text.splitlines()
    if line_no is None or line_no < 1:
        return None
    i = max(0, line_no - 1)
    start = max(0, i - pad)
    end = min(len(lines), i + pad + 1)
    return "\n".join(f"{idx+1:>4}: {lines[idx]}" for idx in range(start, end))

# PDF export
def build_pdf(title, issues, ai_summary):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x_margin, y_margin = inch * 0.75, inch * 0.75
    y = height - y_margin

    def writeln(txt, size=11, leading=14, bold=False):
        nonlocal y
        if y < y_margin + leading:
            c.showPage(); y = height - y_margin
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        for line in txt.split("\n"):
            c.drawString(x_margin, y, line); y -= leading

    writeln(title, size=16, leading=20, bold=True); writeln("")
    writeln("AI Summary", size=13, leading=18, bold=True)
    for para in textwrap.wrap(ai_summary or "(No AI summary)", width=95): writeln(para)
    writeln("")
    writeln("Findings", size=13, leading=18, bold=True)

    if not issues:
        writeln("No issues detected by current rules.")
    else:
        for idx, it in enumerate(issues, 1):
            header = f"{idx}. [{it['severity'].upper()}] {it['category']} – {it['message']}"
            writeln(header, bold=True)
            meta = []
            if it.get("id"): meta.append(f"Rule: {it['id']}")
            if it.get("line"): meta.append(f"Line: {it['line']}")
            if meta: writeln("  " + " | ".join(meta))
            if it.get("evidence"):
                ev = "\n".join("  " + s for s in it["evidence"].split("\n"))
                writeln("Evidence:"); writeln(ev)
            if it.get("remediation"):
                for para in textwrap.wrap("Remediation: " + it["remediation"], width=95):
                    writeln("  " + para)
            writeln("")

    c.showPage(); c.save(); buf.seek(0)
    return buf

# AI summary
def ethical_report(issues, language):
    if not issues:
        return f"No major issues detected by the current {language} rules."
    prompt = {
        "role": "user",
        "content": (
            f"You are a precise ethics/security reviewer for {language} code. "
            "Given these structured findings, produce a concise report:\n"
            "1) Executive summary (1–2 lines)\n"
            "2) Top risks with why they matter (bullets)\n"
            "3) Quick fixes (bullets)\n\n"
            f"Findings JSON:\n{issues}"
        )
    }
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "You write clear, actionable audit summaries."}, prompt],
            max_tokens=500, temperature=0.2,
        )
        return resp.choices[0].message["content"].strip()
    except Exception as e:
        return f"(LLM summary unavailable) {e}"

# PYTHON ANALYZER
import ast

BIAS_KEYWORDS_PY = re.compile(r"\b(race|ethnicity|gender|sex|religion|caste|skin[_ ]?tone|disability|age_group)\b", re.I)
SECRET_PATTERNS_PY = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    (re.compile(r"sk_(live|test)_[0-9a-zA-Z]{20,}"), "Stripe Secret Key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "Generic API Key"),
]
PII_PATTERNS_PY = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "Email address"),
    (re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "Phone number"),
]
SQL_EXEC_PATTERN_PY = re.compile(r"\.execute\s*\(\s*(f?['\"].*(SELECT|INSERT|UPDATE|DELETE).*)", re.I | re.S)
SQL_CONCAT_RISK_PY = re.compile(r"\.execute\s*\(\s*(?:f?['\"]).*['\"]\s*\+\s*", re.S)
TRAIN_TEST_SPLIT_PY = re.compile(r"train_test_split\s*\(", re.I)


def analyze_python(code: str):
    issues = []
    lines = code.splitlines()

    # regex-based checks
    for rx, label in SECRET_PATTERNS_PY:
        for m in rx.finditer(code):
            ln = code[:m.start()].count("\n") + 1
            add_issue(issues, "Security", "high", f"Possible {label} hardcoded.",
                      ln, snippet(code, ln),
                      "Move secrets to env vars or a secret manager.", "PY-SEC-001")

    cred_rx = re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*=\s*['\"][^'\"]+['\"]")
    for m in cred_rx.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "high", "Hardcoded credential found.",
                  ln, snippet(code, ln),
                  "Use env vars/secret manager; never commit credentials.", "PY-SEC-002")

    for rx, label in PII_PATTERNS_PY:
        for m in rx.finditer(code):
            ln = code[:m.start()].count("\n") + 1
            add_issue(issues, "Privacy", "medium", f"Potential PII ({label}) present in code.",
                      ln, snippet(code, ln),
                      "Avoid real PII in code; use anonymized samples.", "PY-PRI-001")

    for i, line in enumerate(lines):
        if BIAS_KEYWORDS_PY.search(line):
            add_issue(issues, "Ethics/Bias", "medium",
                      "Sensitive attribute referenced. Assess for bias.",
                      i+1, snippet(code, i+1),
                      "If used for modeling, justify and test fairness; mitigate if needed.", "PY-ETH-001")
        if SQL_EXEC_PATTERN_PY.search(line):
            if ("f\"" in line or "f'" in line) or SQL_CONCAT_RISK_PY.search(line):
                add_issue(issues, "Security", "high",
                          "Possible SQL injection via string interpolation/concatenation.",
                          i+1, snippet(code, i+1),
                          "Use parameterized queries.", "PY-SEC-003")
        if TRAIN_TEST_SPLIT_PY.search(line) and "stratify=" not in line:
            add_issue(issues, "ML Practice", "low",
                      "train_test_split without stratify (imbalance risk).",
                      i+1, snippet(code, i+1),
                      "Provide stratify=labels for classification.", "PY-ML-001")

    # AST checks
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        add_issue(issues, "Quality", "low", f"SyntaxError: {e}", None, None, "Fix syntax errors.", "PY-QLT-001")
        return issues

    class PyVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                add_issue(issues, "Security", "high",
                          f"Use of {node.func.id}() is dangerous.",
                          node.lineno, None, "Avoid eval/exec.", "PY-SEC-004")

            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "pickle" and node.func.attr in {"loads", "load"}:
                    add_issue(issues, "Security", "high",
                              "Unsafe deserialization via pickle.",
                              node.lineno, None, "Prefer JSON; trust inputs only.", "PY-SEC-005")
                if node.func.value.id == "yaml" and node.func.attr == "load":
                    safe = any(k.arg == "Loader" and getattr(k.value, "id", "") in {"SafeLoader","FullLoader"} for k in node.keywords)
                    if not safe:
                        add_issue(issues, "Security", "high",
                                  "yaml.load without SafeLoader.",
                                  node.lineno, None, "Use yaml.safe_load or specify SafeLoader.", "PY-SEC-006")
                if node.func.value.id == "hashlib" and node.func.attr in {"md5", "sha1"}:
                    add_issue(issues, "Security", "medium",
                              f"Weak hash {node.func.attr} detected.",
                              node.lineno, None, "Use SHA-256+, or bcrypt/argon2 for passwords.", "PY-SEC-007")

            if isinstance(node.func, ast.Attribute):
                if getattr(node.func.value, "id", "") == "subprocess" and node.func.attr in {"run","Popen","call"}:
                    shell_true = any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords)
                    if shell_true:
                        add_issue(issues, "Security", "high",
                                  "subprocess called with shell=True.",
                                  node.lineno, None, "Avoid shell=True; pass arg list.", "PY-SEC-008")

            if isinstance(node.func, ast.Name) and node.func.id == "system":
                add_issue(issues, "Security", "medium", "System command execution detected.",
                          node.lineno, None, "Prefer subprocess without shell; validate inputs.", "PY-SEC-009")

            if isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", "") == "random":
                if node.func.attr in {"random","randint","randrange"}:
                    add_issue(issues, "Security", "low", "Non-crypto randomness possibly used for tokens.",
                              node.lineno, None, "Use secrets module for tokens.", "PY-SEC-010")
            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler):
            if node.type is None or (isinstance(node.type, ast.Name) and node.type.id in {"Exception","BaseException"}):
                add_issue(issues, "Quality", "low", "Over-broad exception handler.",
                          node.lineno, None, "Catch specific exceptions.", "PY-QLT-002")
            self.generic_visit(node)

    PyVisitor().visit(tree)
    sev_order = {"critical":0,"high":1,"medium":2,"low":3}
    issues.sort(key=lambda x: (sev_order.get(x["severity"], 4), x["category"]))
    return issues

# TREE-SITTER HELPERS (JS/Java/C/C++)


LANG_MAP = {
    "JavaScript": "javascript",
    "Java": "java",
    "C": "c",
    "C++": "cpp",
}

def ts_get_parser(lang_key: str):
    if not TREE_SITTER_AVAILABLE:
        return None, None
    try:
        lang = getattr(tsl, f"get_language")(LANG_MAP[lang_key])
        parser = Parser(); parser.set_language(lang)
        return parser, lang
    except Exception:
        return None, None


def ts_root(parser, code: str):
    if not parser:
        return None
    tree = parser.parse(bytes(code, "utf8"))
    return tree.root_node


def ts_iter_matches(lang, root, query_src: str, code: str):
    from tree_sitter import Query
    q = Query(lang, query_src)
    for m in q.matches(root, bytes(code, "utf8")):
        yield m

# JAVASCRIPT ANALYZER (AST + regex)

# Regex MVP (shared across languages)
GENERIC_SECRET_RX = re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]")
PLAIN_HTTP_RX = re.compile(r"\bhttp://", re.I)
BIAS_RX_GENERIC = re.compile(r"\b(race|ethnicity|gender|sex|religion|caste|skin[_ ]?tone|disability|age)\b", re.I)


def analyze_js(code: str):
    issues = []

    # AST checks via tree-sitter 
    parser, lang = ts_get_parser("JavaScript")
    root = ts_root(parser, code)
    if root:
        # 1) eval(...) calls
        q_eval = """
        (call_expression
          function: (identifier) @fn
          arguments: (arguments))
        """
        for m in ts_iter_matches(lang, root, q_eval, code):
            for cap in m.captures:
                node = cap[0]
                if node.text.decode() == "eval":
                    ln = node.start_point[0] + 1
                    add_issue(issues, "Security", "high", "Use of eval() is dangerous.", ln, snippet(code, ln),
                              "Avoid eval; use safe parsing or explicit logic.", "JS-SEC-001")
        # 2) assignment to element.innerHTML
        q_inner = """
        (assignment_expression
          left: (member_expression
                  object: (_)
                  property: (property_identifier) @prop)
          right: (_))
        """
        for m in ts_iter_matches(lang, root, q_inner, code):
            for cap in m.captures:
                node = cap[0]
                if node.text.decode() == "innerHTML":
                    ln = node.start_point[0] + 1
                    add_issue(issues, "Security", "medium", "Assignment to innerHTML can enable XSS.", ln, snippet(code, ln),
                              "Prefer textContent or sanitize HTML before insertion.", "JS-SEC-002")
        # 3) new Function(...)
        q_new_fn = """
        (new_expression
          constructor: (identifier) @ctor
          arguments: (arguments))
        """
        for m in ts_iter_matches(lang, root, q_new_fn, code):
            for cap in m.captures:
                if cap[0].text.decode() == "Function":
                    ln = cap[0].start_point[0] + 1
                    add_issue(issues, "Security", "high", "Dynamic code execution via new Function().", ln, snippet(code, ln),
                              "Avoid dynamic code execution.", "JS-SEC-003")

    # Regex MVP
    for m in GENERIC_SECRET_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "high", "Hardcoded credential found.", ln, snippet(code, ln),
                  "Use env vars/secrets; never commit credentials.", "JS-SEC-004")
    for m in PLAIN_HTTP_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "medium", "Plain HTTP request detected.", ln, snippet(code, ln),
                  "Use HTTPS to prevent MITM.", "JS-SEC-005")
    for m in BIAS_RX_GENERIC.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Ethics/Bias", "medium", "Sensitive attribute referenced.", ln, snippet(code, ln),
                  "Document justification; test/mitigate bias.", "JS-ETH-001")

    return issues

# JAVA ANALYZER (AST + regex)

def analyze_java(code: str):
    issues = []

    # AST (best-effort patterns)
    parser, lang = ts_get_parser("Java")
    root = ts_root(parser, code)
    if root:
        # Runtime.getRuntime().exec(...)
        q_exec = """
        (method_invocation
          object: (method_invocation
                    object: (identifier) @obj
                    name: (identifier) @m1)
          name: (identifier) @m2)
        """
        for m in ts_iter_matches(lang, root, q_exec, code):
            caps = {capname: node for node, capname in [(c[0], m.pattern.capture_names[c[1]]) for c in m.captures]}
            if caps.get('obj') and caps['obj'].text.decode() == 'Runtime' and caps.get('m1') and caps['m1'].text.decode() == 'getRuntime' and caps.get('m2') and caps['m2'].text.decode() == 'exec':
                ln = caps['m2'].start_point[0] + 1
                add_issue(issues, "Security", "high", "Command execution via Runtime.exec().", ln, snippet(code, ln),
                          "Avoid exec; use safe APIs and validate inputs.", "JV-SEC-001")
        # MessageDigest.getInstance("MD5"|"SHA-1")
        q_md = """
        (method_invocation
          object: (field_access
                    object: (identifier) @obj
                    field: (identifier) @field)
          name: (identifier) @name
          arguments: (argument_list (string_literal) @alg))
        """
        for m in ts_iter_matches(lang, root, q_md, code):
            caps = {capname: node for node, capname in [(c[0], m.pattern.capture_names[c[1]]) for c in m.captures]}
            if caps.get('obj') and caps['obj'].text.decode() == 'MessageDigest' and caps.get('name') and caps['name'].text.decode() == 'getInstance':
                alg = caps['alg'].text.decode().strip('"')
                if alg in ("MD5", "SHA-1"):
                    ln = caps['name'].start_point[0] + 1
                    add_issue(issues, "Security", "medium", f"Weak hash algorithm {alg}.", ln, snippet(code, ln),
                              "Use SHA-256+; for passwords use bcrypt/argon2.", "JV-SEC-002")

    # Regex MVP
    # SQL concat in executeQuery/executeUpdate
    rx_sql = re.compile(r"execute(Query|Update)\s*\(\s*\".*\"\s*\+\s*", re.S)
    for m in rx_sql.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "high", "Possible SQL injection via string concatenation.", ln, snippet(code, ln),
                  "Use PreparedStatement with placeholders.", "JV-SEC-003")
    for m in GENERIC_SECRET_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "high", "Hardcoded credential found.", ln, snippet(code, ln),
                  "Use env vars/secrets.", "JV-SEC-004")
    for m in PLAIN_HTTP_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "medium", "Plain HTTP endpoint referenced.", ln, snippet(code, ln),
                  "Use HTTPS.", "JV-SEC-005")
    for m in BIAS_RX_GENERIC.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Ethics/Bias", "medium", "Sensitive attribute referenced.", ln, snippet(code, ln),
                  "Justify use; test/mitigate bias.", "JV-ETH-001")

    return issues

# C / C++ ANALYZER (AST + regex)

DANGEROUS_C_FUNCS = {
    "gets": "Use gets() is unsafe (buffer overflow).",
    "strcpy": "strcpy without bounds can overflow.",
    "strcat": "strcat without bounds can overflow.",
    "sprintf": "sprintf without bounds can overflow (use snprintf).",
    "system": "system() executes shell commands (command injection).",
    "popen": "popen() spawns shell; validate inputs.",
    "rand": "rand() is not cryptographically secure.",
}

FORMAT_STRING_FUNC = {"printf", "fprintf", "sprintf"}

C_WEAK_HASH_RX = re.compile(r"\b(MD5|SHA1)_Init\b|EVP_md5\(\)|EVP_sha1\(\)")


def analyze_c_or_cpp(code: str, lang_name: str):
    issues = []

    parser, lang = ts_get_parser("C++" if lang_name == "C++" else "C")
    root = ts_root(parser, code)
    if root:
        # Function calls by identifier
        q_call = """
        (call_expression
          function: (identifier) @fn)
        """
        for m in ts_iter_matches(lang, root, q_call, code):
            fn_node = m.captures[0][0]
            fn = fn_node.text.decode()
            if fn in DANGEROUS_C_FUNCS:
                ln = fn_node.start_point[0] + 1
                add_issue(issues, "Security", "high" if fn in {"gets","system","popen"} else "medium",
                          DANGEROUS_C_FUNCS[fn], ln, snippet(code, ln),
                          "Use safer alternatives (fgets, strncpy/strlcpy, snprintf, exec without shell, arc4random/openssl RAND).",
                          f"C-SEC-{fn.upper()}")
        # printf-style calls with non-literal first argument (format string vuln heuristic)
        q_printf = """
        (call_expression
          function: (identifier) @fn
          arguments: (argument_list . (identifier) @arg))
        """
        for m in ts_iter_matches(lang, root, q_printf, code):
            caps = {capname: node for node, capname in [(c[0], m.pattern.capture_names[c[1]]) for c in m.captures]}
            fn = caps.get('fn').text.decode() if caps.get('fn') else None
            if fn in FORMAT_STRING_FUNC:
                ln = caps['fn'].start_point[0] + 1
                add_issue(issues, "Security", "high", "Potential format string vulnerability (non-literal format).", ln, snippet(code, ln),
                          "Ensure the first printf-style argument is a literal format string.", "C-SEC-FMTSTR")

    # Regex MVP
    for m in GENERIC_SECRET_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "high", "Hardcoded credential found.", ln, snippet(code, ln),
                  "Do not embed secrets in source; use config.", "C-SEC-SECRET")
    for m in PLAIN_HTTP_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "medium", "Plain HTTP endpoint referenced.", ln, snippet(code, ln),
                  "Use HTTPS.", "C-SEC-HTTP")
    for m in BIAS_RX_GENERIC.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Ethics/Bias", "medium", "Sensitive attribute referenced.", ln, snippet(code, ln),
                  "Avoid disparate treatment; document justification.", "C-ETH-001")
    for m in C_WEAK_HASH_RX.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        add_issue(issues, "Security", "medium", "Weak hash algorithm usage (MD5/SHA1).", ln, snippet(code, ln),
                  "Use SHA-256+; for passwords use bcrypt/scrypt/argon2.", "C-SEC-WEAKHASH")

    return issues

# UI now


st.set_page_config(page_title="AI Code Ethics Auditor — Multilanguage", page_icon="🧭", layout="wide")
st.title("🧭 AI-Powered Code Ethics Auditor — Multilanguage (Python, JS, Java, C, C++)")

languages = ["Python", "JavaScript", "Java", "C", "C++"]
language = st.selectbox("Choose language", languages, index=0)

colL, colR = st.columns([3,2], gap="large")

with colR:
    st.markdown("**Checks included (varies by language):**")
    st.markdown("""
- Hardcoded secrets/credentials
- PII hints (emails/phones)
- Plain HTTP endpoints
- Bias indicators (sensitive attrs)
- SQL injection patterns (where applicable)
- Dangerous functions / dynamic code exec
- Weak hashes (MD5/SHA1)
- OS command execution risks
- Non-crypto randomness for tokens (where applicable)
- Format string risks (C/C++)
- Python-specific: pickle/yaml.load, subprocess shell=True, broad exceptions, train_test_split without stratify
    """)
    if not TREE_SITTER_AVAILABLE and language != "Python":
        st.warning("tree-sitter not installed — using regex-only checks for non-Python languages. Install with: pip install tree_sitter tree_sitter_languages")

with colL:
    upload_types = {
        "Python": ["py"],
        "JavaScript": ["js", "ts"],
        "Java": ["java"],
        "C": ["c", "h"],
        "C++": ["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
    }
    uploaded_file = st.file_uploader(f"Upload a {language} file", type=upload_types[language])
    code_text = st.text_area("Or paste your code here:", height=260, placeholder=f"Paste {language} code…")

    code = None
    if uploaded_file:
        code = uploaded_file.read().decode("utf-8", errors="ignore")
    elif code_text.strip():
        code = code_text

    run_btn = st.button(f"Run {language} Analysis", type="primary", use_container_width=True)

if run_btn and not code:
    st.error("Please upload or paste some code first.")

if run_btn and code:
    with st.spinner("Analyzing…"):
        if language == "Python":
            findings = analyze_python(code)
        elif language == "JavaScript":
            findings = analyze_js(code)
        elif language == "Java":
            findings = analyze_java(code)
        else:
            findings = analyze_c_or_cpp(code, language)

    st.success(f"{language} analysis complete — {len(findings)} issue(s) found.")

    st.subheader("Findings")
    if not findings:
        st.write("No issues found by current rule set.")
    else:
        for f in findings:
            line_str = f" (Line {f['line']})" if f.get("line") else ""
            with st.expander(f"[{f['severity'].upper()}] {f['category']} — {f['message']}{line_str}", expanded=False):
                st.write(f"**Rule:** {f.get('id','-')}")
                if f.get("evidence"):
                    lang_hint = "python" if language=="Python" else ("javascript" if language=="JavaScript" else ("java" if language=="Java" else "c"))
                    st.code(f["evidence"], language=lang_hint)
                if f.get("remediation"):
                    st.markdown(f"**Remediation:** {f['remediation']}")

    st.subheader("AI Ethical Summary")
    if not openai.api_key:
        st.warning("Set OPENAI_API_KEY to generate the AI report.")
        ai_report = f"AI report unavailable (missing OPENAI_API_KEY)."
    else:
        ai_report = ethical_report(findings, language)
        st.write(ai_report)

    st.subheader("Export")
    pdf_buf = build_pdf(f"AI Code Ethics Auditor — {language} Report", findings, ai_report)
    st.download_button(
        label="📄 Download PDF Report",
        data=pdf_buf,
        file_name=f"ethics_audit_report_{language.lower().replace('+','p')}.pdf",
        mime="application/pdf",
        use_container_width=True
    )
