"""Precision and recall tests for the Python AST detector pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom.models.analysis import Reachability, SourceContext, ValueResolution
from aibom.models.entities import EntityType, Model, Service
from aibom.service import run_scan


def _scan(tmp_path: Path, code: str, *, relative: str = "app.py", disabled: set[str] | None = None):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return run_scan(tmp_path, disabled_detectors=disabled).inventory


def _models(inventory: Any) -> list[Model]:
    return [e for e in inventory.by_type(EntityType.MODEL) if isinstance(e, Model)]


def _services(inventory: Any) -> list[Service]:
    return [e for e in inventory.by_type(EntityType.SERVICE) if isinstance(e, Service)]


def test_openai_alias_dict_fstring_and_environment_default(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "import os\n"
        "from openai import OpenAI as OA\n"
        'VERSION = "4.1"\n'
        'CONFIG = {"model": f"gpt-{VERSION}"}\n'
        'MODEL = os.getenv("MODEL_NAME", CONFIG["model"])\n'
        "client = OA()\n"
        "client.responses.create(model=MODEL)\n",
    )

    model = next(model for model in _models(inventory) if model.name == "gpt-4.1")
    assert model.detector_ids == ["python.openai.ast"]
    assert model.environment_variable == "MODEL_NAME"
    assert model.value_resolution is ValueResolution.RESOLVED
    assert model.usage.invoked is True
    assert {step.operation for step in model.resolution_path} >= {
        "environment_default",
        "subscript",
        "fstring",
        "variable_reference",
    }


def test_anthropic_alias_and_dictionary_value(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "import anthropic as ai\n"
        'SETTINGS = {"model": "claude-sonnet-4"}\n'
        "client = ai.Anthropic()\n"
        'client.messages.create(model=SETTINGS["model"], max_tokens=64)\n',
    )

    model = next(model for model in _models(inventory) if model.name == "claude-sonnet-4")
    assert model.provider == "anthropic"
    assert model.detector_ids == ["python.anthropic.ast"]
    service = next(service for service in _services(inventory) if service.name == "anthropic")
    assert service.usage.imported is True
    assert service.usage.instantiated is True
    assert service.usage.invoked is True


def test_environment_without_default_remains_unresolved(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "import os\n"
        "from openai import OpenAI\n"
        'MODEL = os.environ["MODEL_NAME"]\n'
        "client = OpenAI()\n"
        "client.responses.create(model=MODEL)\n",
    )

    model = next(model for model in _models(inventory) if model.name == "unresolved:MODEL_NAME")
    assert model.environment_variable == "MODEL_NAME"
    assert model.value_resolution is ValueResolution.UNRESOLVED
    assert model.confidence_factors.value_resolution_confidence < 1.0


def test_resolution_path_does_not_leak_unrelated_config_secret(tmp_path: Path) -> None:
    secret = "sk-abcdef0123456789ABCDEF0123"
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        f'CONFIG = {{"model": "gpt-4.1", "api_key": "{secret}"}}\n'
        "client = OpenAI()\n"
        'client.responses.create(model=CONFIG["model"])\n',
    )
    model = next(model for model in _models(inventory) if model.name == "gpt-4.1")
    assert secret not in model.model_dump_json()


def test_secret_shaped_model_argument_is_redacted(tmp_path: Path) -> None:
    secret = "sk-abcdef0123456789ABCDEF0123"
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        f'MODEL = "{secret}"\n'
        "client = OpenAI()\n"
        "client.responses.create(model=MODEL)\n",
    )
    model = next(model for model in _models(inventory) if model.name.startswith("redacted:"))
    assert secret not in model.model_dump_json()
    assert model.value_resolution is ValueResolution.UNRESOLVED


def test_comments_docstrings_and_unused_values_are_not_models(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        '"""client.responses.create(model="gpt-doc-example")"""\n'
        '# client.responses.create(model="gpt-comment")\n'
        "from openai import OpenAI\n"
        'UNUSED_MODEL = "gpt-unused"\n',
    )

    assert not _models(inventory)
    service = next(service for service in _services(inventory) if service.name == "openai")
    assert service.usage.imported is True
    assert service.usage.instantiated is False
    assert service.usage.invoked is False


def test_simple_wrapper_argument_is_traced(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def ask(model):\n"
        "    return client.responses.create(model=model)\n"
        'ask("gpt-4.1")\n',
    )

    model = next(model for model in _models(inventory) if model.name == "gpt-4.1")
    assert any(step.operation == "literal" for step in model.resolution_path)
    assert model.value_resolution is ValueResolution.RESOLVED


def test_factory_created_openai_client_is_recognized(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "def create_client(config):\n"
        "    return OpenAI(**config)\n"
        "client = create_client({})\n"
        'client.responses.create(model="gpt-factory")\n',
    )
    model = next(model for model in _models(inventory) if model.name == "gpt-factory")
    assert model.detector_ids == ["python.openai.ast"]
    assert model.usage.invoked is True


def test_openai_assistants_create_is_recognized(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.beta.assistants.create(model="gpt-assistant")\n',
    )
    model = next(model for model in _models(inventory) if model.name == "gpt-assistant")
    assert model.usage.invoked is True


def test_openai_custom_endpoint_is_provider_scoped_and_sanitized(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        'client = OpenAI(base_url="https://user:secret@example.test/v1?token=hidden")\n',
    )
    endpoint = next(service for service in _services(inventory) if service.name.startswith("https"))
    assert endpoint.name == "https://example.test/v1"
    assert "secret" not in endpoint.model_dump_json()
    assert "hidden" not in endpoint.model_dump_json()


def test_malformed_custom_endpoint_does_not_abort_scan(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        'client = OpenAI(base_url="https://example.test:not-a-port/v1")\n',
    )
    assert any(service.name == "openai" for service in _services(inventory))
    assert not any(service.name.startswith("https://") for service in _services(inventory))


def test_same_file_route_reachability_is_true_false_or_unknown(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from fastapi import FastAPI\n"
        "from openai import OpenAI\n"
        "app = FastAPI()\n"
        "client = OpenAI()\n"
        "def helper():\n"
        '    return client.responses.create(model="gpt-reachable")\n'
        '@app.post("/chat")\n'
        "def chat():\n"
        "    return helper()\n"
        "def unused():\n"
        '    return client.responses.create(model="gpt-unreachable")\n',
    )

    models = {model.name: model for model in _models(inventory)}
    assert models["gpt-reachable"].usage.reachable is Reachability.TRUE
    assert models["gpt-reachable"].reachability_path == ["http_route:chat", "helper"]
    assert models["gpt-unreachable"].usage.reachable is Reachability.FALSE


def test_main_guard_reaches_called_function(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run():\n"
        '    return client.responses.create(model="gpt-cli")\n'
        'if __name__ == "__main__":\n'
        "    run()\n",
    )
    model = next(model for model in _models(inventory) if model.name == "gpt-cli")
    assert model.usage.reachable is Reachability.TRUE
    assert model.reachability_path == ["python.__main__", "run"]


def test_source_context_classifies_tests(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        'from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(model="gpt-test")\n',
        relative="tests/test_client.py",
    )
    assert _models(inventory)[0].source_contexts == [SourceContext.TEST]


def test_syntax_error_uses_legacy_fallback(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        'client.responses.create(model="gpt-4o-mini")\nif (\n',
    )
    model = next(model for model in _models(inventory) if model.name == "gpt-4o-mini")
    assert model.detector_ids == ["legacy.regex"]
    assert inventory.stats.parse_errors


def test_detector_can_be_disabled_by_stable_id(tmp_path: Path) -> None:
    inventory = _scan(
        tmp_path,
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        'client.responses.create(model="gpt-disabled")\n',
        disabled={"python.openai.ast"},
    )
    assert not _models(inventory)
    assert "python.openai.ast" not in inventory.stats.detectors_run
