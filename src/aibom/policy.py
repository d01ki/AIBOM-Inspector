"""Default analysis scope for risk, graphs, and behavioral paths.

The complete inventory retains test, fixture, example, and documentation
components. Security scoring and attack-path claims focus on production
evidence so deliberately vulnerable regression fixtures do not make their host
repository appear vulnerable.
"""

from __future__ import annotations

from aibom.inventory import Inventory
from aibom.models.analysis import SourceContext
from aibom.models.entities import Entity, EntityType, Package
from aibom.models.signals import RiskSignal


def entity_in_production_scope(entity: Entity) -> bool:
    """Treat unclassified legacy entities as production for compatibility."""
    return (
        not entity.source_contexts
        or SourceContext.PRODUCTION in entity.source_contexts
    )


def signal_in_production_scope(signal: RiskSignal) -> bool:
    return signal.source_context is SourceContext.PRODUCTION


def production_view(inventory: Inventory) -> Inventory:
    """Return a shallow, non-mutating view containing production evidence."""
    view = inventory.model_copy(deep=False)
    view.entities = [
        entity for entity in inventory.entities if entity_in_production_scope(entity)
    ]
    entity_ids = {entity.id for entity in view.entities}
    view.relationships = [
        relationship
        for relationship in inventory.relationships
        if relationship.source_id in entity_ids and relationship.target_id in entity_ids
    ]
    view.signals = [
        signal
        for signal in inventory.signals
        if signal_in_production_scope(signal)
    ]
    return view


def production_ai_component_count(inventory: Inventory) -> int:
    """Count AI-relevant entities in the production policy view."""
    return sum(
        1
        for entity in production_view(inventory).entities
        if entity.type is not EntityType.PACKAGE
        or (isinstance(entity, Package) and entity.ai)
    )
