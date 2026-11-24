"""Export the integration OpenAPI and draft 2020-12 schema from the real router."""

import json
from pathlib import Path

from app.integration.api import integration_openapi
from app.main import create_app


def main() -> None:
    spec = integration_openapi(create_app().state.integration_router)
    schemas = {
        name: json.loads(
            json.dumps(schema).replace("#/components/schemas/", "#/$defs/")
        )
        for name, schema in spec["components"]["schemas"].items()
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "NetGuard Integration Contract v1 message catalog",
        "$defs": schemas,
    }
    directory = Path(__file__).resolve().parents[2] / "docs" / "contracts"
    for filename, content in (
        ("integration-v1.openapi.json", spec),
        ("integration-v1.schema.json", schema),
    ):
        (directory / filename).write_text(
            json.dumps(content, indent=2, sort_keys=True) + "\n"
        )


if __name__ == "__main__":
    main()
