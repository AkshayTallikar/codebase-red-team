"""Patchers: the arms race with the reference catalog, and the LLM patcher's contract."""

from redteam.agents.patcher import LLMPatcher, ReferencePatcher
from redteam.gate import VerificationGate
from redteam.llm import FakeBackend, LLMRefusal
from redteam.models import Edit, Finding, Probe
from redteam.oracle import Oracle
from redteam.sandbox import Sandbox, load_seed_source

SQLI = Probe(
    "GET", "/notes/search", "GET /notes/search", vuln_class="sqli", params={"q": "' OR 1=1 --"}
)
SQLI_BYPASS = Probe(
    "GET", "/notes/search", "GET /notes/search", vuln_class="sqli", params={"q": "' or 1=1 --"}
)
TRAVERSAL = Probe(
    "GET", "/files", "GET /files", vuln_class="path_traversal", params={"name": "../secrets.txt"}
)
TRAVERSAL_BYPASS = Probe(
    "GET", "/files", "GET /files", vuln_class="path_traversal", params={"name": "....//secrets.txt"}
)
TRAVERSAL_LINE = '        path = os.path.join(data_dir, "public", name)\n'


def _finding(probe: Probe, source: str) -> Finding:
    """Send the probe to a sandbox running `source` and return the oracle's finding."""
    with Sandbox(source) as sandbox:
        finding = Oracle(sandbox.canary).judge(sandbox.send(probe))
    assert finding is not None, f"{probe.path} {probe.params} did not trigger the oracle"
    return finding


def _accepted_source(result) -> str:
    assert result.accepted, result.reasons
    assert result.source is not None
    return result.source


def test_sqli_arms_race_with_reference_catalog():
    gate = VerificationGate()
    patcher = ReferencePatcher()
    seed = load_seed_source()

    first = _finding(SQLI, seed)
    round_one = patcher.propose(first, seed, 0)
    assert round_one is not None
    after_naive = _accepted_source(gate.verify(seed, round_one, first, []))

    bypass = _finding(SQLI_BYPASS, after_naive)
    round_two = patcher.propose(bypass, after_naive, 1)
    assert round_two is not None
    after_correct = _accepted_source(
        gate.verify(after_naive, round_two, bypass, [SQLI, SQLI_BYPASS])
    )
    assert "title LIKE ?" in after_correct
    assert '" OR " in q' not in after_correct


def test_traversal_arms_race_with_reference_catalog():
    gate = VerificationGate()
    patcher = ReferencePatcher()
    seed = load_seed_source()

    first = _finding(TRAVERSAL, seed)
    round_one = patcher.propose(first, seed, 0)
    assert round_one is not None
    after_naive = _accepted_source(gate.verify(seed, round_one, first, []))

    bypass = _finding(TRAVERSAL_BYPASS, after_naive)
    round_two = patcher.propose(bypass, after_naive, 1)
    assert round_two is not None
    _accepted_source(gate.verify(after_naive, round_two, bypass, [TRAVERSAL, TRAVERSAL_BYPASS]))


def test_reference_patcher_returns_none_when_exhausted_or_unknown():
    seed = load_seed_source()
    finding = _finding(SQLI, seed)
    patcher = ReferencePatcher()
    assert patcher.propose(finding, seed, 2) is None
    assert patcher.propose(finding, seed, -1) is None

    unknown = Finding(
        kind="leak",
        vuln_class="xss",
        endpoint="GET /notes",
        probe=Probe("GET", "/notes", "GET /notes"),
        status=200,
        evidence="",
    )
    assert patcher.propose(unknown, seed, 0) is None


def test_llm_patcher_returns_patch_from_canned_response():
    seed = load_seed_source()
    finding = _finding(TRAVERSAL, seed)
    backend = FakeBackend(
        [
            {
                "rationale": "Resolve the real path and check containment.",
                "edits": [{"old": TRAVERSAL_LINE, "new": TRAVERSAL_LINE + "        pass\n"}],
            }
        ]
    )
    patch = LLMPatcher(backend).propose(finding, seed, 0)
    assert patch is not None
    assert patch.author == "llm"
    assert patch.finding_key == finding.key
    assert patch.edits == (Edit(old=TRAVERSAL_LINE, new=TRAVERSAL_LINE + "        pass\n"),)


def test_llm_patcher_returns_none_on_refusal():
    seed = load_seed_source()
    finding = _finding(SQLI, seed)
    backend = FakeBackend([LLMRefusal("declined", category="policy")])
    assert LLMPatcher(backend).propose(finding, seed, 0) is None


def test_llm_patcher_returns_none_on_empty_edits():
    seed = load_seed_source()
    finding = _finding(SQLI, seed)
    backend = FakeBackend([{"rationale": "nothing to do", "edits": []}])
    assert LLMPatcher(backend).propose(finding, seed, 0) is None


def test_llm_patcher_returns_none_on_malformed_response():
    seed = load_seed_source()
    finding = _finding(SQLI, seed)
    backend = FakeBackend(
        [
            {"rationale": "missing edits"},
            {"rationale": "edits not a list", "edits": "oops"},
            {"rationale": "bad item", "edits": [{"old": "x"}]},
        ]
    )
    patcher = LLMPatcher(backend)
    for _ in range(3):
        assert patcher.propose(finding, seed, 0) is None


def test_llm_prompt_contains_key_and_source_but_never_the_canary():
    seed = load_seed_source()
    with Sandbox(seed) as sandbox:
        canary = sandbox.canary
        finding = Oracle(canary).judge(sandbox.send(SQLI))
    assert finding is not None
    backend = FakeBackend(
        [{"rationale": "fix", "edits": [{"old": "def search_notes", "new": "def search_notes"}]}]
    )
    LLMPatcher(backend).propose(finding, seed, 1)

    prompt = backend.calls[0]["prompt"]
    assert finding.key in prompt
    assert "def search_notes" in prompt
    assert canary not in prompt
    assert canary not in backend.calls[0]["system"]
