"""LLM and deterministic model adapters for CodeReviewGraph."""
import json
from typing import Any, List, Optional
from langchain_core.messages import BaseMessage, AIMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import ChatResult, ChatGeneration
from codereviewgraph.core.config import settings
from codereviewgraph.core.security_rules import scan_security_rules, scan_quality_rules, analyze_ast


class DeterministicCodeAuditorModel(BaseChatModel):
    """Deterministic, rule-backed mock chat model for offline test gates and predictable analysis.
    
    Guarantees 100% test gate determinism, fast execution, zero external API costs,
    and returns valid structured evaluations for any prompt.
    """

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[Any] = None,
        **kwargs: Any,
    ) -> ChatResult:
        last_message = messages[-1].content if messages else ""
        
        # Analyze input content for task type
        response_text = self._compute_response(str(last_message))
        generation = ChatGeneration(message=AIMessage(content=response_text))
        return ChatResult(generations=[generation])

    def _compute_response(self, prompt: str) -> str:
        """Route prompt based on agent node role and return valid JSON."""
        # Check if this is a security audit request
        if "SECURITY_AUDIT" in prompt:
            code = self._extract_code(prompt)
            findings = scan_security_rules(code)
            return json.dumps({"findings": findings})

        # Quality audit request
        elif "QUALITY_AUDIT" in prompt:
            code = self._extract_code(prompt)
            findings = scan_quality_rules(code)
            return json.dumps({"findings": findings})

        # Refactoring patch generation request
        elif "GENERATE_PATCH" in prompt:
            code = self._extract_code(prompt)
            patches = self._generate_patches(code)
            return json.dumps({"patches": patches})

        # Default reflection / critic
        elif "VERIFY_FINDINGS" in prompt:
            return json.dumps({
                "verdict": "VERIFIED",
                "adjusted_findings": [],
                "confidence": 0.95
            })

        return json.dumps({"status": "SUCCESS", "message": "Analysis completed."})

    def _extract_code(self, prompt: str) -> str:
        """Extract code block or return full prompt."""
        if "```" in prompt:
            parts = prompt.split("```")
            if len(parts) >= 3:
                code_part = parts[1]
                if code_part.startswith("python"):
                    return code_part[6:].strip()
                return code_part.strip()
        return prompt

    def _generate_patches(self, code: str) -> List[dict]:
        """Generate deterministic drop-in patches for known security patterns."""
        patches = []
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            if "eval(" in line:
                patched = line.replace("eval(", "ast.literal_eval(")
                patches.append({
                    "finding_id": f"SEC-002-{i}",
                    "original_snippet": line.strip(),
                    "patched_snippet": patched.strip(),
                    "explanation": "Replaced dangerous eval() with ast.literal_eval() to prevent arbitrary code execution."
                })
            elif "shell=True" in line:
                patched = line.replace("shell=True", "shell=False")
                patches.append({
                    "finding_id": f"SEC-003-{i}",
                    "original_snippet": line.strip(),
                    "patched_snippet": patched.strip(),
                    "explanation": "Disabled shell=True to eliminate command injection vulnerability."
                })
            elif "SELECT" in line.upper() and ("f\"" in line or "f'" in line):
                patches.append({
                    "finding_id": f"SEC-001-{i}",
                    "original_snippet": line.strip(),
                    "patched_snippet": "# Use parameterized query instead of f-string interpolation\ncursor.execute('SELECT * FROM table WHERE id = ?', (user_id,))",
                    "explanation": "Replaced string interpolation in SQL query with parameterized binding."
                })
        return patches

    @property
    def _llm_type(self) -> str:
        return "deterministic-code-auditor"


def get_chat_model(provider: Optional[str] = None) -> BaseChatModel:
    """Factory function to instantiate chat model based on configuration."""
    active_provider = provider or settings.llm_provider
    
    if active_provider == "gemini" and settings.gemini_api_key:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                model="gemini-2.5-flash",
                google_api_key=settings.gemini_api_key,
                temperature=settings.temperature
            )
        except Exception:
            # Fallback to deterministic model if network or key issue
            return DeterministicCodeAuditorModel()

    return DeterministicCodeAuditorModel()
