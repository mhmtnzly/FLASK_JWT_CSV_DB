"""empty message

Revision ID: c3440cd7f7b8
Revises: 
Create Date: 2022-12-15 00:08:31.655962

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3440cd7f7b8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('public_id', sa.String(length=50), nullable=True),
    sa.Column('name', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=80), nullable=False),
    sa.Column('password', sa.String(length=150), nullable=False),
    sa.Column('admin', sa.Boolean(), nullable=True),
    sa.Column('confirmed', sa.Boolean(), nullable=True),
    sa.Column('confirmed_on', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('name'),
    sa.UniqueConstraint('public_id')
    )
    op.create_table('nasdaq',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=10), nullable=False),
    sa.Column('date', sa.DateTime(), nullable=True),
    sa.Column('low', sa.Float(), nullable=True),
    sa.Column('open', sa.Float(), nullable=True),
    sa.Column('volume', sa.BigInteger(), nullable=True),
    sa.Column('high', sa.Float(), nullable=True),
    sa.Column('close', sa.Float(), nullable=True),
    sa.Column('adjustedClose', sa.Float(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('nasdaq')
    op.drop_table('user')
    # ### end Alembic commands ###
