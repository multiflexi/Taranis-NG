"""empty message

Revision ID: 094b85ef4dcf
Revises: 7607d7d98f71
Create Date: 2021-11-22 11:14:22.259612

"""

import uuid
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy import orm, and_
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# revision identifiers, used by Alembic.
revision = "094b85ef4dcf"
down_revision = "7607d7d98f71"
branch_labels = None
depends_on = None


class OSINTSourceRev094b85ef4dcf(Base):
    __tablename__ = "osint_source"
    id = sa.Column(sa.String(64), primary_key=True)


class OSINTSourceGroupRev094b85ef4dcf(Base):
    __tablename__ = "osint_source_group"
    id = sa.Column(sa.String(64), primary_key=True)
    name = sa.Column(sa.String(), nullable=False)
    description = sa.Column(sa.String())
    default = sa.Column(sa.Boolean(), default=False)

    @staticmethod
    def get_all_with_source(session, osint_source_id):
        all_groups = session.query(OSINTSourceGroupRev094b85ef4dcf).all()
        groups = []
        for group in all_groups:
            for source in group.osint_sources:
                if source.id == osint_source_id:
                    groups.append(group)
                    break

        return groups


class OSINTSourceGroupOSINTSourceRev094b85ef4dcf(Base):
    __tablename__ = "osint_source_group_osint_source"
    osint_source_group_id = sa.Column(sa.String, sa.ForeignKey("osint_source_group.id"), primary_key=True)
    osint_source_id = sa.Column(sa.String, sa.ForeignKey("osint_source.id"), primary_key=True)


class NewsItemDataRev094b85ef4dcf(Base):
    __tablename__ = "news_item_data"
    id = sa.Column(sa.String(64), primary_key=True)
    hash = sa.Column(sa.String())
    title = sa.Column(sa.String())
    review = sa.Column(sa.String())
    author = sa.Column(sa.String())
    source = sa.Column(sa.String())
    link = sa.Column(sa.String())
    language = sa.Column(sa.String())
    content = sa.Column(sa.String())
    collected = sa.Column(sa.DateTime)
    published = sa.Column(sa.String())
    updated = sa.Column(sa.DateTime, default=datetime.now())
    osint_source_id = sa.Column(sa.String, sa.ForeignKey("osint_source.id"), nullable=True)


class NewsItemRev094b85ef4dcf(Base):
    __tablename__ = "news_item"
    id = sa.Column(sa.Integer, primary_key=True)
    news_item_data_id = sa.Column(sa.String, sa.ForeignKey("news_item_data.id"))
    news_item_aggregate_id = sa.Column(sa.Integer, sa.ForeignKey("news_item_aggregate.id"))


class NewsItemAggregateRev094b85ef4dcf(Base):
    __tablename__ = "news_item_aggregate"
    id = sa.Column(sa.Integer, primary_key=True)
    title = sa.Column(sa.String())
    description = sa.Column(sa.String())
    created = sa.Column(sa.DateTime)
    read = sa.Column(sa.Boolean, default=False)
    important = sa.Column(sa.Boolean, default=False)
    likes = sa.Column(sa.Integer, default=0)
    dislikes = sa.Column(sa.Integer, default=0)
    relevance = sa.Column(sa.Integer, default=0)
    comments = sa.Column(sa.String(), default="")
    osint_source_group_id = sa.Column(sa.String, sa.ForeignKey("osint_source_group.id"))


class NewsItemAggregateSearchIndexRev094b85ef4dcf(Base):
    __tablename__ = "news_item_aggregate_search_index"
    id = sa.Column(sa.Integer, primary_key=True)
    data = sa.Column(sa.String)
    news_item_aggregate_id = sa.Column(sa.Integer, sa.ForeignKey("news_item_aggregate.id"))

    @staticmethod
    def prepare(session, aggregate):
        search_index = session.query(NewsItemAggregateSearchIndexRev094b85ef4dcf).filter_by(news_item_aggregate_id=aggregate.id).first()
        if search_index is None:
            search_index = NewsItemAggregateSearchIndexRev094b85ef4dcf()
            search_index.news_item_aggregate_id = aggregate.id
            session.add(search_index)

        data = aggregate.title
        data += " " + aggregate.description
        data += " " + aggregate.comments

        for news_item in session.query(NewsItemRev094b85ef4dcf).filter(NewsItemRev094b85ef4dcf.news_item_aggregate_id == aggregate.id):
            news_item_data = session.query(NewsItemDataRev094b85ef4dcf).get(news_item.news_item_data_id)
            data += " " + news_item_data.title
            data += " " + news_item_data.review
            data += " " + news_item_data.content
            data += " " + news_item_data.author
            data += " " + news_item_data.link

        search_index.data = data.lower()


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    op.add_column("osint_source_group", sa.Column("default", sa.Boolean(), nullable=True))

    for group in session.query(OSINTSourceGroupRev094b85ef4dcf):
        group.default = False
        session.commit()

    default_group = OSINTSourceGroupRev094b85ef4dcf()
    default_group.id = str(uuid.uuid4())
    default_group.name = "Default"
    default_group.description = "Default group for uncategorized OSINT sources"
    default_group.default = True
    session.add(default_group)
    session.commit()

    query = session.query(OSINTSourceRev094b85ef4dcf)
    query = query.outerjoin(
        OSINTSourceGroupOSINTSourceRev094b85ef4dcf,
        OSINTSourceRev094b85ef4dcf.id == OSINTSourceGroupOSINTSourceRev094b85ef4dcf.osint_source_id,
    )
    query = query.filter(OSINTSourceGroupOSINTSourceRev094b85ef4dcf.osint_source_group_id == None)
    unmapped_sources = set()
    for osint_source in query:
        group_mapping = OSINTSourceGroupOSINTSourceRev094b85ef4dcf()
        group_mapping.osint_source_id = osint_source.id
        group_mapping.osint_source_group_id = default_group.id
        unmapped_sources.add(osint_source.id)
        session.add(group_mapping)
        session.commit()

    query = session.query(NewsItemDataRev094b85ef4dcf)
    query = query.outerjoin(NewsItemRev094b85ef4dcf, NewsItemDataRev094b85ef4dcf.id == NewsItemRev094b85ef4dcf.news_item_data_id)
    query = query.filter(and_(NewsItemRev094b85ef4dcf.id == None, NewsItemDataRev094b85ef4dcf.osint_source_id.in_(unmapped_sources)))
    for news_item_data in query:
        groups = OSINTSourceGroupRev094b85ef4dcf.get_all_with_source(session, news_item_data.osint_source_id)
        for group in groups:
            aggregate = NewsItemAggregateRev094b85ef4dcf()
            aggregate.title = news_item_data.title
            aggregate.description = news_item_data.review
            aggregate.created = news_item_data.collected
            aggregate.osint_source_group_id = group.id
            session.add(aggregate)

            news_item = NewsItemRev094b85ef4dcf()
            news_item.news_item_data_id = news_item_data.id
            news_item.news_item_aggregate_id = aggregate.id
            session.add(news_item)

            NewsItemAggregateSearchIndexRev094b85ef4dcf.prepare(session, aggregate)
            session.commit()


# ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("osint_source_group", "default")
    # ### end Alembic commands ###
