"""empty message

Revision ID: 610dfbea8075
Revises: 84f982ce4200
Create Date: 2021-11-08 14:03:16.520226

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import orm
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# revision identifiers, used by Alembic.
revision = "610dfbea8075"
down_revision = "84f982ce4200"
branch_labels = None
depends_on = None


class WordListREV610dfbea8075(Base):
    __tablename__ = "word_list"
    id = sa.Column(sa.Integer, primary_key=True)
    description = sa.Column(sa.String(), nullable=False)


class WordListCategoryREV610dfbea8075(Base):
    __tablename__ = "word_list_category"
    id = sa.Column(sa.Integer, primary_key=True)
    description = sa.Column(sa.String(), nullable=False)


class WordListEntryREV610dfbea8075(Base):
    __tablename__ = "word_list_entry"
    id = sa.Column(sa.Integer, primary_key=True)
    description = sa.Column(sa.String(), nullable=False)


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    for word_list in session.query(WordListREV610dfbea8075):
        if word_list.description is None:
            word_list.description = ""

    for word_list_category in session.query(WordListCategoryREV610dfbea8075):
        if word_list_category.description is None:
            word_list_category.description = ""

    for word_list_entry in session.query(WordListEntryREV610dfbea8075):
        if word_list_entry.description is None:
            word_list_entry.description = ""

    session.commit()

    op.alter_column("word_list", "description", existing_type=sa.VARCHAR(), nullable=False)

    op.alter_column("word_list_category", "description", existing_type=sa.VARCHAR(), nullable=False)

    op.alter_column("word_list_entry", "description", existing_type=sa.VARCHAR(), nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column("word_list", "description", existing_type=sa.VARCHAR(), nullable=True)
    # ### end Alembic commands ###
