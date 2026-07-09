"""unique dt project per ef_project_id and name

Revision ID: 777888973479
Revises: 844bb24a18ad
Create Date: 2026-07-09 14:02:51.244341

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '777888973479'
down_revision: Union[str, Sequence[str], None] = '844bb24a18ad'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Enforce that a product_name maps to one DT project per EF project.

    Replaces the (name, parent_uuid) uniqueness with (ef_project_id, name), which
    is what the runtime relies on (find_dt_project resolves the upload target by
    ef_project_id + name via scalar_one_or_none()). Fails if existing rows already
    violate it — that is intentional; such data was already ambiguous.
    """
    op.drop_constraint(
        "dependency_track_projects_name_parent_uuid_key",
        "dependency_track_projects",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_dependency_track_projects_ef_project_id_name",
        "dependency_track_projects",
        ["ef_project_id", "name"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "uq_dependency_track_projects_ef_project_id_name",
        "dependency_track_projects",
        type_="unique",
    )
    op.create_unique_constraint(
        "dependency_track_projects_name_parent_uuid_key",
        "dependency_track_projects",
        ["name", "parent_uuid"],
    )
