"""migrationdomain

Revision ID: d3f7223b3b63
Revises: 
Create Date: 2023-06-23 11:47:05.866790

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd3f7223b3b63'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'urls',
        sa.Column('url', sa.TEXT),
        sa.Column('scanid', sa.TEXT), 
        sa.Column('maldomain', sa.TEXT), 
        sa.Column('domain_score' ,sa.TEXT), 
        sa.Column('url_phishing_prob', sa.TEXT),
        sa.Column('domain_type',sa.TEXT),
        sa.Column('dga_score', sa.TEXT),
        sa.Column('realip', sa.TEXT),
        sa.Column('domain_created', sa.TEXT),
        sa.Column('abuse_record_total', sa.TEXT),
        sa.Column('fake_https_url', sa.TEXT),
        sa.Column('suspicious_url', sa.TEXT)

    )


def downgrade():
    op.drop_table('urls')
