"""empty message

Revision ID: b54abff67c66
Revises: 
Create Date: 2022-02-11 23:10:26.498467

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b54abff67c66'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('blog_posts', sa.Column('author_name', sa.String(), nullable=True))
    op.create_foreign_key(None, 'blog_posts', 'users', ['author_name'], ['username'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'blog_posts', type_='foreignkey')
    op.drop_column('blog_posts', 'author_name')
    # ### end Alembic commands ###
