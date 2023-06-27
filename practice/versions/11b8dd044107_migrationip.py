"""migrationip

Revision ID: 11b8dd044107
Revises: d3f7223b3b63
Create Date: 2023-06-23 11:57:11.752903

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '11b8dd044107'
down_revision = 'd3f7223b3b63'
branch_labels = None
depends_on = None


def upgrade() -> None:
        op.create_table(
        'ips',
        sa.Column('public_ip', sa.TEXT),
        sa.Column('port', sa.TEXT), 
        sa.Column('app', sa.TEXT), 
        sa.Column('inbound_outbound' ,sa.TEXT), 
        sa.Column('tags', sa.TEXT),
        sa.Column('representative',sa.TEXT),
        sa.Column('ids', sa.TEXT),
        sa.Column('abuse', sa.TEXT),
        sa.Column('verification', sa.TEXT),

    )



def downgrade() -> None:
    op.drop_table('ips')
